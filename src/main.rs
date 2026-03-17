mod config;
mod ip_map;
mod mtproto;
mod pool;
mod proxy;
mod stats;
mod websocket;

#[cfg(feature = "gui")]
mod gui;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use config::Config;
use stats::Stats;

#[derive(Parser)]
#[command(
    name = "tg-proxy",
    about = "Telegram WebSocket bridge proxy\n\n\
             Tunnels Telegram Desktop/Mobile traffic over WebSocket (port 443)\n\
             to bypass DPI firewalls that block raw Telegram IP ranges.\n\n\
             Mobile: use --host 0.0.0.0 and set SOCKS5 in Telegram Mobile\n\
             to your LAN IP:port."
)]
struct Cli {
    /// Listen host (0.0.0.0 to expose on LAN for mobile)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Listen port
    #[arg(long, short, default_value_t = 1080)]
    port: u16,

    /// Target IP for a DC, format DC:IP  (repeatable)
    #[arg(
        long = "dc-ip",
        value_name = "DC:IP",
        default_values = ["2:149.154.167.220", "4:149.154.167.220"]
    )]
    dc_ips: Vec<String>,

    /// Enable debug logging
    #[arg(short, long)]
    verbose: bool,

    /// Disable TLS certificate verification (insecure)
    #[arg(long)]
    skip_tls_verify: bool,

    /// Pre-warmed WebSocket connections per DC
    #[arg(long, default_value_t = 4)]
    pool_size: usize,

    /// Maximum age of a pooled connection in seconds
    #[arg(long, default_value_t = 120)]
    pool_max_age: u64,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,

    /// Launch the tray + GUI window (requires --features gui build)
    #[cfg(feature = "gui")]
    #[arg(long)]
    gui: bool,
}

fn parse_dc_ips(entries: &[String]) -> anyhow::Result<HashMap<u8, Ipv4Addr>> {
    let mut map = HashMap::new();
    for entry in entries {
        let (dc_str, ip_str) = entry
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Invalid --dc-ip {:?}: expected DC:IP", entry))?;
        let dc: u8 = dc_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid DC number {:?}", dc_str))?;
        let ip = Ipv4Addr::from_str(ip_str)
            .map_err(|_| anyhow::anyhow!("Invalid IP {:?}", ip_str))?;
        if !(1..=5).contains(&dc) {
            anyhow::bail!("DC must be 1–5, got {}", dc);
        }
        map.insert(dc, ip);
    }
    Ok(map)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_target(false)
        .init();

    if cli.skip_tls_verify {
        tracing::warn!("TLS certificate verification DISABLED (--skip-tls-verify)");
    }

    let dc_ips = parse_dc_ips(&cli.dc_ips)?;
    if dc_ips.is_empty() {
        anyhow::bail!("No DC IPs configured. Specify at least one --dc-ip DC:IP");
    }

    let config = Arc::new(Config {
        host: cli.host,
        port: cli.port,
        dc_ips,
        pool_size: cli.pool_size,
        pool_max_age: Duration::from_secs(cli.pool_max_age),
        skip_tls_verify: cli.skip_tls_verify,
        connect_timeout: Duration::from_secs(cli.connect_timeout),
    });

    let stats = Arc::new(Stats::new());

    // ── GUI mode ──────────────────────────────────────────────────────────────
    #[cfg(feature = "gui")]
    if cli.gui {
        // gui::run_gui takes over the main thread (required on macOS)
        return gui::run_gui(config, stats);
    }

    // ── CLI mode ──────────────────────────────────────────────────────────────
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let tls = Arc::new(websocket::build_tls_config(config.skip_tls_verify)?);
            let pool = Arc::new(pool::WsPool::new());
            let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            proxy::run(config, stats, tls, pool, stop_rx).await
        })
}
