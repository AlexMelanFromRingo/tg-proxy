use std::path::PathBuf;

use clap::{ArgAction, Parser};
use tg_proxy::config::{
    self, coerce_domain_list, is_valid_domain, load_or_create_secret, parse_dc_ips, parse_secret, SecretSource,
    Settings, DEFAULT_FRONTING_SNI,
};
use tg_proxy::logging::{self, LogFile};
use tg_proxy::upstream::UpstreamSocks;

#[derive(Parser)]
#[command(
    name = "tg-proxy",
    version,
    about = "Telegram proxy over WebSocket — works where Telegram's own IPs are blocked",
    long_about = "Telegram proxy over WebSocket.\n\n\
        Tunnels Telegram traffic through routes that censors rarely block: Telegram's own\n\
        web gateway (plain or with SNI fronting), a free Cloudflare Worker, Cloudflare-proxied\n\
        domains — falling back to raw TCP. Speaks MTProto-proxy (recommended) and SOCKS5\n\
        to the Telegram client.\n\n\
        Run `tg-proxy --check` to test every route on your network."
)]
struct Cli {
    /// Listen address (use 0.0.0.0 to share with phones on your network)
    #[arg(long, default_value = "127.0.0.1", env = "TG_PROXY_HOST")]
    host: String,

    /// SOCKS5 port (0 = off)
    #[arg(short, long, default_value_t = 1080, env = "TG_PROXY_PORT")]
    port: u16,

    /// MTProto-proxy port (0 = off)
    #[arg(long, default_value_t = 1443, env = "TG_PROXY_MTPROTO_PORT")]
    mtproto_port: u16,

    /// MTProto proxy secret, 32 hex characters (default: generated once and remembered)
    #[arg(long, env = "TG_PROXY_SECRET", hide_env_values = true)]
    secret: Option<String>,

    /// Gateway IP for a DC, DC:IP (repeatable). Without a value: no direct connections at all.
    #[arg(
        long = "dc-ip",
        value_name = "DC:IP",
        num_args = 0..=1,
        default_missing_value = "",
        action = ArgAction::Append
    )]
    dc_ips: Option<Vec<String>>,

    /// Disable direct connections to Telegram (same as a bare --dc-ip)
    #[arg(long)]
    no_direct: bool,

    /// Debug logging
    #[arg(short, long)]
    verbose: bool,

    /// Disable TLS certificate verification (insecure!)
    #[arg(long)]
    skip_tls_verify: bool,

    /// Pre-warmed WebSocket connections per DC (0 = off)
    #[arg(long, default_value_t = 4)]
    pool_size: usize,

    /// Maximum age of a pooled connection, seconds
    #[arg(long, default_value_t = 120)]
    pool_max_age: u64,

    /// Close a session after this many seconds without data (0 = never)
    #[arg(long, default_value_t = 300, value_name = "SECS", env = "TG_PROXY_IDLE_TIMEOUT")]
    idle_timeout: u64,

    /// Direct connection timeout, seconds
    #[arg(long, default_value_t = 5)]
    connect_timeout: u64,

    /// Socket send/receive buffer, KB
    #[arg(long, default_value_t = 256, value_name = "KB")]
    buf_kb: usize,

    /// Your own Cloudflare-proxied domain for the CF-proxy route (repeatable)
    #[arg(long = "cfproxy-domain", value_name = "DOMAIN", env = "TG_PROXY_CF_DOMAINS", value_delimiter = ',')]
    cfproxy_domain: Vec<String>,

    /// Your Cloudflare Worker domain (repeatable) — tried before other fallbacks
    #[arg(
        long = "cfproxy-worker-domain",
        value_name = "DOMAIN",
        env = "TG_PROXY_WORKER_DOMAINS",
        value_delimiter = ','
    )]
    cfproxy_worker_domain: Vec<String>,

    /// Do not use Cloudflare-proxied domains (no third-party domain pool)
    #[arg(long)]
    no_cfproxy: bool,

    /// Reach CF-proxy / CF-worker over plain port 80 instead of TLS
    #[arg(long)]
    no_secure: bool,

    /// SNI shown on the wire when plain connections to Telegram are cut
    #[arg(long, default_value = DEFAULT_FRONTING_SNI, value_name = "DOMAIN")]
    fronting_sni: String,

    /// Disable SNI fronting
    #[arg(long)]
    no_fronting: bool,

    /// Enable fake TLS (ee-secret) disguised as this website
    #[arg(long, default_value = "", value_name = "DOMAIN", env = "TG_PROXY_FAKE_TLS_DOMAIN")]
    fake_tls_domain: String,

    /// Send ALL traffic to Telegram's TEST datacenters
    #[arg(long)]
    force_test_dc: bool,

    /// Accept a PROXY protocol v1 header (behind nginx/haproxy)
    #[arg(long)]
    proxy_protocol: bool,

    /// Send all outbound connections through this SOCKS5 proxy: [USER:PASS@]HOST[:PORT]
    #[arg(long, value_name = "ADDR", value_parser = clap::value_parser!(UpstreamSocks), env = "TG_PROXY_UPSTREAM_SOCKS5", hide_env_values = true)]
    upstream_socks5: Option<UpstreamSocks>,

    /// Also write the log to this file (rotated)
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,

    /// Log file size before rotation, MB
    #[arg(long, default_value_t = 5.0, value_name = "MB")]
    log_max_mb: f64,

    /// Rotated log files to keep (at least 1)
    #[arg(long, default_value_t = 1, value_name = "N")]
    log_backups: usize,

    /// Test every route to Telegram from this machine, then exit
    #[arg(long)]
    check: bool,
}

fn build_settings(cli: &Cli) -> anyhow::Result<(Settings, SecretSource)> {
    let dc_redirects = match &cli.dc_ips {
        _ if cli.no_direct => Default::default(),
        None => config::default_dc_redirects(),
        // a bare `--dc-ip` switches direct connections off
        Some(v) if v.iter().any(|e| e.is_empty()) => Default::default(),
        Some(v) => parse_dc_ips(v)?,
    };

    let (secret, source) = match &cli.secret {
        Some(s) => (parse_secret(s)?, SecretSource::Cli),
        None => load_or_create_secret(),
    };

    let fake_tls_domain = cli.fake_tls_domain.trim().to_string();
    if !fake_tls_domain.is_empty() && !is_valid_domain(&fake_tls_domain) {
        anyhow::bail!("--fake-tls-domain must be a domain name, got {:?}", fake_tls_domain);
    }

    let fronting_sni = if cli.no_fronting { String::new() } else { cli.fronting_sni.trim().to_string() };
    if !fronting_sni.is_empty() && !is_valid_domain(&fronting_sni) {
        anyhow::bail!("--fronting-sni must be a domain name, got {:?}", fronting_sni);
    }

    let settings = Settings {
        host: cli.host.clone(),
        socks_port: cli.port,
        mtproto_port: cli.mtproto_port,
        secret,
        dc_redirects,
        buffer_size: cli.buf_kb.max(4) * 1024,
        pool_size: cli.pool_size,
        pool_max_age: std::time::Duration::from_secs(cli.pool_max_age),
        connect_timeout: std::time::Duration::from_secs(cli.connect_timeout.max(1)),
        skip_tls_verify: cli.skip_tls_verify,
        fronting_sni,
        fallback_cfproxy: !cli.no_cfproxy,
        cfproxy_user_domains: coerce_domain_list(&cli.cfproxy_domain),
        cfproxy_worker_domains: coerce_domain_list(&cli.cfproxy_worker_domain),
        disable_secure: cli.no_secure,
        fake_tls_domain,
        proxy_protocol: cli.proxy_protocol,
        force_test_dc: cli.force_test_dc,
        idle_timeout: std::time::Duration::from_secs(cli.idle_timeout),
        gateway_port: 443,
        masking_port: 443,
        upstream_socks5: cli.upstream_socks5.clone().map(std::sync::Arc::new),
    };
    Ok((settings, source))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_file = cli.log_file.clone().map(|path| LogFile { path, max_mb: cli.log_max_mb, backups: cli.log_backups });
    logging::init(cli.verbose, log_file)?;

    if cli.skip_tls_verify {
        tracing::warn!("TLS certificate verification is DISABLED (--skip-tls-verify)");
    }
    let (settings, source) = build_settings(&cli)?;

    if cli.check {
        return tg_proxy::check::run(settings).await;
    }
    tg_proxy::app::run(settings, source).await
}
