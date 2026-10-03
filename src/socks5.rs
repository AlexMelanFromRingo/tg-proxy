//! SOCKS5 front-end (Telegram's "SOCKS5 proxy" setting).
//!
//! The client believes it is talking to a real Telegram DC: it sends its normal
//! obfuscated2 init, with the DC chosen by the destination IP. We forward the
//! stream unchanged over whichever route works. Everything that is not Telegram
//! is passed straight through.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::bridge::{bridge_tcp, bridge_ws, SessionInfo, Splitting, UpPath};
use crate::client::{ClientReader, ClientWriter};
use crate::crypto::{normalize_dc, patch_dc, peek_client_init, stream_decryptor, MsgSplitter, HANDSHAKE_LEN};
use crate::ip_map::{dc_from_ip, is_known_dc, is_telegram_ip};
use crate::route::{DcKey, Request, Route, Router};
use crate::websocket::{tune_socket, Target};

const STEP_TIMEOUT: Duration = Duration::from_secs(10);
const INIT_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn run(router: Arc<Router>, listener: TcpListener) {
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                warn!("SOCKS5 accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let router = router.clone();
        tokio::spawn(async move {
            let _active = router.stats.enter();
            let label = peer.to_string();
            if let Err(e) = handle(sock, label.clone(), router).await {
                debug!("[{}] {}", label, e);
            }
        });
    }
}

fn reply(status: u8) -> [u8; 10] {
    let mut r = [0u8; 10];
    r[0] = 0x05;
    r[1] = status;
    r[3] = 0x01; // IPv4 BND.ADDR
    r
}

/// The passthrough must not become a way into the proxy host or its network.
fn is_forbidden_target(ip: Option<Ipv4Addr>, host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    ip.is_some_and(|ip| {
        ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast()
    })
}

fn is_http_header(data: &[u8]) -> bool {
    [&b"POST "[..], b"GET ", b"HEAD ", b"OPTIONS "].iter().any(|p| data.starts_with(p))
}

async fn step<T>(fut: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    timeout(STEP_TIMEOUT, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))?
}

async fn handle(sock: TcpStream, label: String, router: Arc<Router>) -> io::Result<()> {
    let (mut rd, mut wr) = sock.into_split();

    // ── Greeting ──
    let mut hdr = [0u8; 2];
    step(rd.read_exact(&mut hdr)).await?;
    if hdr[0] != 5 {
        debug!("[{}] not SOCKS5 (ver={})", label, hdr[0]);
        return Ok(());
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    step(rd.read_exact(&mut methods)).await?;
    if !methods.contains(&0x00) {
        wr.write_all(&[0x05, 0xFF]).await?; // no acceptable methods
        return Ok(());
    }
    wr.write_all(&[0x05, 0x00]).await?;

    // ── Request ──
    let mut req = [0u8; 4];
    step(rd.read_exact(&mut req)).await?;
    let (cmd, atyp) = (req[1], req[3]);
    if cmd != 1 {
        wr.write_all(&reply(0x07)).await?;
        return Ok(());
    }

    let (host, ipv4): (String, Option<Ipv4Addr>) = match atyp {
        1 => {
            let mut raw = [0u8; 4];
            step(rd.read_exact(&mut raw)).await?;
            let ip = Ipv4Addr::from(raw);
            (ip.to_string(), Some(ip))
        }
        3 => {
            let mut len = [0u8; 1];
            step(rd.read_exact(&mut len)).await?;
            let mut name = vec![0u8; len[0] as usize];
            step(rd.read_exact(&mut name)).await?;
            let s = String::from_utf8_lossy(&name).into_owned();
            let ip = s.parse().ok();
            (s, ip)
        }
        4 => {
            let mut raw = [0u8; 18];
            step(rd.read_exact(&mut raw)).await?;
            warn!("[{}] IPv6 destinations are not supported: disable IPv6 in Telegram's settings", label);
            wr.write_all(&reply(0x08)).await?;
            return Ok(());
        }
        _ => {
            wr.write_all(&reply(0x08)).await?;
            return Ok(());
        }
    };
    let mut pb = [0u8; 2];
    step(rd.read_exact(&mut pb)).await?;
    let port = u16::from_be_bytes(pb);

    let upstream = router.cfg.upstream_socks5.clone();

    // ── Not Telegram: plain passthrough ──
    let Some(tg_ip) = ipv4.filter(|ip| is_telegram_ip(*ip)) else {
        if is_forbidden_target(ipv4, &host) {
            warn!("[{}] refused passthrough to {}:{} (loopback / private / link-local)", label, host, port);
            wr.write_all(&reply(0x02)).await?; // connection not allowed by ruleset
            return Ok(());
        }
        router.stats.passthrough.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("[{}] passthrough -> {}:{}", label, host, port);
        let target = match ipv4 {
            Some(ip) => Target::Addr(SocketAddr::new(ip.into(), port)),
            None => Target::Host(host.clone(), port),
        };
        let remote = match timeout(STEP_TIMEOUT, crate::upstream::connect(&target, upstream.as_deref())).await {
            Ok(Ok(s)) => s,
            _ => {
                warn!("[{}] passthrough connect to {}:{} failed", label, host, port);
                wr.write_all(&reply(0x05)).await?;
                return Ok(());
            }
        };
        tune_socket(&remote, router.cfg.buffer_size);
        wr.write_all(&reply(0x00)).await?;
        pipe(rd, wr, remote, &label, &router).await;
        return Ok(());
    };

    // ── Telegram: accept, then read the obfuscated2 init ──
    wr.write_all(&reply(0x00)).await?;
    let mut init = [0u8; HANDSHAKE_LEN];
    if !matches!(timeout(INIT_TIMEOUT, rd.read_exact(&mut init)).await, Ok(Ok(_))) {
        debug!("[{}] client disconnected or timed out before its init packet", label);
        return Ok(());
    }
    if is_http_header(&init) {
        router.stats.http_rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("[{}] HTTP transport rejected (use TCP transport)", label);
        return Ok(());
    }

    let dst = (tg_ip, port);
    let resolved = peek_client_init(&init).and_then(|hs| {
        let (dc, media, test) = normalize_dc(hs.dc_raw, router.cfg.force_test_dc);
        if is_known_dc(dc) {
            return Some((hs.proto, dc, media, test, init.to_vec()));
        }
        // The init names no usable DC: derive it from the destination IP instead.
        dc_from_ip(tg_ip).map(|(dc, media)| {
            let mut patched = init.to_vec();
            patch_dc(&mut patched, dc, media);
            (hs.proto, dc, media, test, patched)
        })
    });
    let Some((proto, dc, media, test, init_bytes)) = resolved else {
        warn!("[{}] cannot determine the DC for {} -> plain TCP", label, host);
        let target = Target::Addr(SocketAddr::new(tg_ip.into(), port));
        if let Ok(Ok(mut remote)) = timeout(STEP_TIMEOUT, crate::upstream::connect(&target, upstream.as_deref())).await
        {
            if remote.write_all(&init).await.is_ok() {
                pipe_with_init(rd, wr, remote, &label, &router, "DC?").await;
            }
        }
        return Ok(());
    };

    let request = Request { dc, media, test, label: &label, orig_dst: Some(dst) };
    let Some(route) = router.connect(&request).await else {
        return Ok(());
    };
    let session = SessionInfo {
        label: label.clone(),
        tag: DcKey { dc, media, test }.to_string(),
        stats: router.stats.clone(),
        idle_timeout: router.cfg.idle_timeout,
    };
    let (creader, cwriter) = (ClientReader::Plain(rd), ClientWriter::Plain(wr));

    match route {
        Route::Ws { mut conn, framed, .. } => {
            if let Err(e) = conn.send(&init_bytes).await {
                warn!("[{}] failed to send the init frame: {}", label, e);
                return Ok(());
            }
            let splitting = framed
                .then(|| Splitting { splitter: MsgSplitter::new(proto), decryptor: stream_decryptor(&init_bytes) });
            bridge_ws(creader, cwriter, conn, UpPath::Verbatim, None, splitting, session).await;
        }
        Route::Tcp(mut remote) => {
            if let Err(e) = remote.write_all(&init_bytes).await {
                warn!("[{}] failed to send the init packet: {}", label, e);
                return Ok(());
            }
            bridge_tcp(creader, cwriter, remote, UpPath::Verbatim, None, session).await;
        }
    }
    Ok(())
}

async fn pipe(rd: OwnedReadHalf, wr: OwnedWriteHalf, remote: TcpStream, label: &str, router: &Arc<Router>) {
    let session = SessionInfo {
        label: label.to_string(),
        tag: "passthrough".into(),
        stats: router.stats.clone(),
        idle_timeout: Duration::ZERO,
    };
    bridge_tcp(ClientReader::Plain(rd), ClientWriter::Plain(wr), remote, UpPath::Verbatim, None, session).await;
}

async fn pipe_with_init(
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    remote: TcpStream,
    label: &str,
    router: &Arc<Router>,
    tag: &str,
) {
    info!("[{}] {} plain TCP", label, tag);
    let session = SessionInfo {
        label: label.to_string(),
        tag: tag.to_string(),
        stats: router.stats.clone(),
        idle_timeout: router.cfg.idle_timeout,
    };
    bridge_tcp(ClientReader::Plain(rd), ClientWriter::Plain(wr), remote, UpPath::Verbatim, None, session).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_blocks_loopback_and_lan() {
        for ip in [[127, 0, 0, 1], [10, 1, 2, 3], [192, 168, 0, 5], [172, 16, 0, 1], [169, 254, 169, 254], [0, 0, 0, 0]]
        {
            assert!(is_forbidden_target(Some(Ipv4Addr::from(ip)), "x"), "{ip:?}");
        }
        assert!(is_forbidden_target(None, "LocalHost") && is_forbidden_target(None, "a.localhost"));
        assert!(!is_forbidden_target(Some(Ipv4Addr::new(93, 184, 216, 34)), "example.org"));
        assert!(!is_forbidden_target(None, "example.org"));
    }
}
