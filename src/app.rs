//! Assembles the running proxy: listeners, background tasks, banner, shutdown.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::{hex, link_host, SecretSource, Settings};
use crate::logging::colors_enabled;
use crate::route::Router;
use crate::stats::Stats;

pub async fn run(cfg: Settings, secret_source: SecretSource) -> anyhow::Result<()> {
    if cfg.mtproto_port == 0 && cfg.socks_port == 0 {
        anyhow::bail!("nothing to listen on: both --port and --mtproto-port are 0");
    }
    let cfg = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let router = Router::new(cfg.clone(), stats.clone())?;

    let mtproto = bind(&cfg.host, cfg.mtproto_port, "MTProto").await?;
    let socks = bind(&cfg.host, cfg.socks_port, "SOCKS5").await?;

    print_banner(&cfg, &secret_source);
    router.start_background();

    {
        let (stats, router) = (stats.clone(), router.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                info!("stats: {} | ws_bl: {}", stats.summary(), router.blacklist_summary());
            }
        });
    }
    if let Some(l) = mtproto {
        tokio::spawn(crate::mtproxy::run(router.clone(), l));
    }
    if let Some(l) = socks {
        tokio::spawn(crate::socks5::run(router.clone(), l));
    }

    shutdown_signal().await;
    info!("Shutting down. Final stats: {}", stats.summary());
    Ok(())
}

async fn bind(host: &str, port: u16, what: &str) -> anyhow::Result<Option<TcpListener>> {
    if port == 0 {
        return Ok(None);
    }
    let l = TcpListener::bind((host, port)).await.with_context(|| {
        format!("cannot listen for {what} on {host}:{port} (is it already in use? try another port)")
    })?;
    Ok(Some(l))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                match term.as_mut() {
                    Some(t) => { t.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn describe_routes(cfg: &Settings) -> String {
    let mut parts = Vec::new();
    if cfg.dc_redirects.is_empty() {
        parts.push("direct WS off".to_string());
    } else {
        let mut dcs: Vec<_> = cfg.dc_redirects.keys().collect();
        dcs.sort();
        let list: Vec<String> = dcs.iter().map(|d| format!("DC{d}")).collect();
        let front = if cfg.fronting_sni.is_empty() { "" } else { " + SNI fronting" };
        parts.push(format!("direct WS ({}){}", list.join(", "), front));
    }
    if !cfg.cfproxy_worker_domains.is_empty() {
        parts.push(format!("CF worker x{}", cfg.cfproxy_worker_domains.len()));
    }
    if cfg.fallback_cfproxy {
        if cfg.cfproxy_user_domains.is_empty() {
            parts.push("CF proxy (community pool)".to_string());
        } else {
            parts.push(format!("CF proxy (your domains x{})", cfg.cfproxy_user_domains.len()));
        }
    }
    parts.push("raw TCP".to_string());
    parts.join(" → ")
}

fn print_banner(cfg: &Settings, secret: &SecretSource) {
    let on = colors_enabled();
    let paint = |code: &str, s: &str| if on { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() };
    let (bold, dim, cyan, yellow) =
        (|s: &str| paint("1", s), |s: &str| paint("2", s), |s: &str| paint("36", s), |s: &str| paint("33", s));

    let host = link_host(&cfg.host);
    let title = format!("tg-proxy v{}", env!("CARGO_PKG_VERSION"));
    let tagline = "Telegram over WebSocket · SNI fronting · Cloudflare";
    let width = tagline.chars().count() + 4;
    eprintln!();
    eprintln!("  {}", dim(&format!("╭{}╮", "─".repeat(width))));
    eprintln!("  {}  {}{}  {}", dim("│"), bold(&title), " ".repeat(width - 4 - title.chars().count()), dim("│"));
    eprintln!("  {}  {}  {}", dim("│"), dim(tagline), dim("│"));
    eprintln!("  {}", dim(&format!("╰{}╯", "─".repeat(width))));
    eprintln!();

    let row = |k: &str, v: String| eprintln!("  {}  {}", dim(&format!("{k:<14}")), v);
    if cfg.mtproto_port != 0 {
        row("MTProto proxy", format!("{}:{}", cfg.host, cfg.mtproto_port));
    }
    if cfg.socks_port != 0 {
        row("SOCKS5 proxy", format!("{}:{}", cfg.host, cfg.socks_port));
    }
    row("Routes", describe_routes(cfg));
    if !cfg.fake_tls_domain.is_empty() {
        row("Fake TLS", cfg.fake_tls_domain.clone());
    }
    if let Some(up) = &cfg.upstream_socks5 {
        row("Upstream", format!("SOCKS5 {up}"));
    }
    if cfg.mtproto_port != 0 {
        let note = match secret {
            SecretSource::Cli => "from --secret".to_string(),
            SecretSource::Loaded(p) => format!("saved in {}", p.display()),
            SecretSource::Generated(p) => format!("new, saved in {}", p.display()),
            SecretSource::Ephemeral => "temporary: changes on every start (use --secret)".to_string(),
        };
        row("Secret", note);
    }
    eprintln!();

    eprintln!("  {}", bold("Add to Telegram (click the link or paste it into a chat):"));
    if cfg.mtproto_port != 0 {
        let s = hex(&cfg.secret);
        let secret_arg = if cfg.fake_tls_domain.is_empty() {
            format!("dd{s}")
        } else {
            format!("ee{s}{}", hex(cfg.fake_tls_domain.as_bytes()))
        };
        eprintln!("    {}", cyan(&format!("tg://proxy?server={host}&port={}&secret={secret_arg}", cfg.mtproto_port)));
    }
    if cfg.socks_port != 0 {
        eprintln!("    {}", cyan(&format!("tg://socks?server={host}&port={}", cfg.socks_port)));
    }
    let loopback = matches!(cfg.host.as_str(), "127.0.0.1" | "localhost" | "::1");
    if !loopback {
        eprintln!();
        if cfg.socks_port != 0 {
            eprintln!(
                "  {}",
                yellow("! The SOCKS5 port has no password: anyone who can reach this address can use it.")
            );
        }
        eprintln!("  {}", yellow("! Do not expose these ports to the Internet unless you mean to run a public proxy."));
    }
    eprintln!();
}
