use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::ip_map::{dc_from_ip, is_telegram_ip, ws_domains};
use crate::mtproto::{extract_dc, patch_dc, MsgSplitter};
use crate::pool::{DcKey, WsPool};
use crate::stats::{human_bytes, Stats};
use crate::websocket::{self, build_frame, recv_frame, send_close, send_frame, send_frames, TlsStream, WsFrame};

const RECV_BUF: usize = 65536;
const COOLDOWN_SECS: u64 = 60;

pub async fn run(
    config: Arc<Config>,
    stats: Arc<Stats>,
    tls: Arc<ClientConfig>,
    pool: Arc<WsPool>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use tokio::net::TcpListener;

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;

    info!("{}", "=".repeat(60));
    info!("  Telegram WS Bridge Proxy (Rust)");
    info!("  Listening on  {}", addr);
    info!("  Target DC IPs:");
    for (dc, ip) in &config.dc_ips {
        info!("    DC{}: {}", dc, ip);
    }
    info!("{}", "=".repeat(60));
    info!("  Telegram Desktop: SOCKS5 → {}  (no auth)", addr);
    info!("  Mobile (LAN):     tg://socks?server=<YOUR-LAN-IP>&port={}", config.port);
    info!("{}", "=".repeat(60));

    let ws_blacklist: Arc<Mutex<HashSet<DcKey>>> = Arc::new(Mutex::new(HashSet::new()));
    let dc_fail_until: Arc<Mutex<HashMap<DcKey, Instant>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Stats logger
    {
        let stats = Arc::clone(&stats);
        let bl = Arc::clone(&ws_blacklist);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let bl_str = {
                    let bl = bl.lock().await;
                    if bl.is_empty() {
                        "none".to_string()
                    } else {
                        let mut keys: Vec<_> = bl.iter().collect();
                        keys.sort();
                        keys.iter()
                            .map(|(d, m)| format!("DC{}{}", d, if *m { "m" } else { "" }))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                };
                info!("stats: {} | ws_bl: {}", stats.summary(), bl_str);
            }
        });
    }

    pool.warmup(&config, Arc::clone(&tls)).await;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, peer) = match accept_result {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Accept error: {}", e);
                        continue;
                    }
                };
                let _ = socket.set_nodelay(true);

                let config = Arc::clone(&config);
                let stats = Arc::clone(&stats);
                let tls = Arc::clone(&tls);
                let pool = Arc::clone(&pool);
                let ws_blacklist = Arc::clone(&ws_blacklist);
                let dc_fail_until = Arc::clone(&dc_fail_until);

                tokio::spawn(async move {
                    handle_client(socket, peer, config, stats, tls, pool, ws_blacklist, dc_fail_until)
                        .await;
                });
            }
            _ = stop.changed() => {
                info!("Proxy shutdown signal received");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_client(
    socket: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    stats: Arc<Stats>,
    tls: Arc<ClientConfig>,
    pool: Arc<WsPool>,
    ws_blacklist: Arc<Mutex<HashSet<DcKey>>>,
    dc_fail_until: Arc<Mutex<HashMap<DcKey, Instant>>>,
) {
    stats.total.fetch_add(1, Relaxed);
    let label = peer.to_string();
    let (reader, writer) = socket.into_split();

    if let Err(e) = handle_inner(
        reader, writer, label.clone(), config, stats, tls, pool, ws_blacklist, dc_fail_until,
    )
    .await
    {
        debug!("[{}] {}", label, e);
    }
}

async fn handle_inner(
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    label: String,
    config: Arc<Config>,
    stats: Arc<Stats>,
    tls: Arc<ClientConfig>,
    pool: Arc<WsPool>,
    ws_blacklist: Arc<Mutex<HashSet<DcKey>>>,
    dc_fail_until: Arc<Mutex<HashMap<DcKey, Instant>>>,
) -> std::io::Result<()> {
    // ── SOCKS5 greeting ──────────────────────────────────────────────────────
    let mut hdr = [0u8; 2];
    timeout(reader.read_exact(&mut hdr), 10).await??;

    if hdr[0] != 5 {
        debug!("[{}] not SOCKS5 (ver={})", label, hdr[0]);
        return Ok(());
    }

    let mut methods = vec![0u8; hdr[1] as usize];
    timeout(reader.read_exact(&mut methods), 10).await??;

    writer.write_all(b"\x05\x00").await?; // no-auth accepted
    writer.flush().await?;

    // ── SOCKS5 CONNECT ───────────────────────────────────────────────────────
    let mut req = [0u8; 4];
    timeout(reader.read_exact(&mut req), 10).await??;
    let (_ver, cmd, _rsv, atyp) = (req[0], req[1], req[2], req[3]);

    if cmd != 1 {
        writer.write_all(&socks5_reply(0x07)).await?;
        writer.flush().await?;
        return Ok(());
    }

    let (dst_host, dst_ipv4): (String, Option<Ipv4Addr>) = match atyp {
        1 => {
            let mut raw = [0u8; 4];
            timeout(reader.read_exact(&mut raw), 10).await??;
            let ip = Ipv4Addr::from(raw);
            (ip.to_string(), Some(ip))
        }
        3 => {
            let mut dlen = [0u8; 1];
            timeout(reader.read_exact(&mut dlen), 10).await??;
            let mut domain = vec![0u8; dlen[0] as usize];
            timeout(reader.read_exact(&mut domain), 10).await??;
            let s = String::from_utf8_lossy(&domain).into_owned();
            let ip = s.parse().ok();
            (s, ip)
        }
        4 => {
            let mut raw = [0u8; 16];
            timeout(reader.read_exact(&mut raw), 10).await??;
            let mut port_buf = [0u8; 2];
            timeout(reader.read_exact(&mut port_buf), 10).await??;
            let port = u16::from_be_bytes(port_buf);
            let addr = std::net::Ipv6Addr::from(raw);
            warn!(
                "[{}] IPv6 not supported: [{}]:{} — disable IPv6 in Telegram settings",
                label, addr, port
            );
            writer.write_all(&socks5_reply(0x05)).await?;
            writer.flush().await?;
            return Ok(());
        }
        _ => {
            writer.write_all(&socks5_reply(0x08)).await?;
            writer.flush().await?;
            return Ok(());
        }
    };

    let mut port_buf = [0u8; 2];
    timeout(reader.read_exact(&mut port_buf), 10).await??;
    let port = u16::from_be_bytes(port_buf);

    // ── Non-Telegram: passthrough ─────────────────────────────────────────────
    let tg_ip = match dst_ipv4.filter(|ip| is_telegram_ip(*ip)) {
        Some(ip) => ip,
        None => {
            stats.passthrough.fetch_add(1, Relaxed);
            debug!("[{}] passthrough -> {}:{}", label, dst_host, port);

            let remote = match timeout(
                TcpStream::connect(format!("{}:{}", dst_host, port)),
                10,
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    warn!("[{}] passthrough connect failed to {}:{}", label, dst_host, port);
                    writer.write_all(&socks5_reply(0x05)).await?;
                    writer.flush().await?;
                    return Ok(());
                }
            };
            let _ = remote.set_nodelay(true);

            writer.write_all(&socks5_reply(0x00)).await?;
            writer.flush().await?;

            let (mut rr, mut rw) = remote.into_split();
            let t1 = tokio::spawn(async move { pipe_drain(reader, rw).await });
            let t2 = tokio::spawn(async move { pipe_drain(rr, writer).await });
            let _ = tokio::join!(t1, t2);
            return Ok(());
        }
    };

    // ── Telegram DC: send SOCKS5 success, read MTProto init ──────────────────
    writer.write_all(&socks5_reply(0x00)).await?;
    writer.flush().await?;

    let mut init = [0u8; 64];
    match timeout(reader.read_exact(&mut init), 15).await {
        Ok(Ok(_)) => {}
        _ => {
            debug!("[{}] client disconnected or timeout waiting for init", label);
            return Ok(());
        }
    }

    if is_http_header(&init) {
        stats.http_rejected.fetch_add(1, Relaxed);
        debug!("[{}] HTTP transport rejected", label);
        return Ok(());
    }

    // ── Resolve DC ────────────────────────────────────────────────────────────
    let (dc, is_media, init_bytes, was_patched) = resolve_dc(tg_ip, &init, &config);

    let Some(dc) = dc else {
        warn!("[{}] unknown DC for {} -> TCP passthrough", label, dst_host);
        tcp_fallback(reader, writer, &dst_host, port, &init_bytes, &label, &stats, None, false)
            .await;
        return Ok(());
    };

    if config.dc_ip(dc).is_none() {
        warn!("[{}] DC{} not in config -> TCP passthrough", label, dc);
        tcp_fallback(reader, writer, &dst_host, port, &init_bytes, &label, &stats, None, false)
            .await;
        return Ok(());
    }

    let dc_key: DcKey = (dc, is_media);
    let target_ip = config.dc_ip(dc).unwrap();
    let media_tag = if is_media { "m" } else { "" };

    // ── WS blacklist ──────────────────────────────────────────────────────────
    if ws_blacklist.lock().await.contains(&dc_key) {
        debug!("[{}] DC{}{} blacklisted -> TCP fallback", label, dc, media_tag);
        tcp_fallback(reader, writer, &dst_host, port, &init_bytes, &label, &stats, Some(dc), is_media)
            .await;
        return Ok(());
    }

    // ── Cooldown ──────────────────────────────────────────────────────────────
    if let Some(&until) = dc_fail_until.lock().await.get(&dc_key) {
        if Instant::now() < until {
            let secs = until.duration_since(Instant::now()).as_secs();
            debug!("[{}] DC{}{} cooldown ({}s) -> TCP fallback", label, dc, media_tag, secs);
            tcp_fallback(reader, writer, &dst_host, port, &init_bytes, &label, &stats, Some(dc), is_media)
                .await;
            return Ok(());
        }
    }

    // ── Try WebSocket ─────────────────────────────────────────────────────────
    let domains = ws_domains(dc, is_media);
    let ws_stream = try_ws_connect(
        target_ip, &domains, &dc_key, &label, dc, media_tag, &dst_host, port,
        &config, &tls, &pool, &stats, &ws_blacklist, &dc_fail_until,
    )
    .await;

    let Some(ws_stream) = ws_stream else {
        info!("[{}] DC{}{} -> TCP fallback to {}:{}", label, dc, media_tag, dst_host, port);
        tcp_fallback(reader, writer, &dst_host, port, &init_bytes, &label, &stats, Some(dc), is_media)
            .await;
        return Ok(());
    };

    // ── Bridge TCP <-> WebSocket ──────────────────────────────────────────────
    stats.ws.fetch_add(1, Relaxed);
    dc_fail_until.lock().await.remove(&dc_key);

    let splitter = if was_patched { MsgSplitter::new(&init_bytes) } else { None };

    let (ws_read, mut ws_write) = tokio::io::split(ws_stream);

    // Send the init packet as the first WebSocket frame
    if let Err(e) = send_frame(&mut ws_write, &init_bytes).await {
        warn!("[{}] failed to send init frame: {}", label, e);
        return Ok(());
    }

    bridge_ws(
        reader, writer, ws_read, ws_write,
        splitter, label, stats, dc, media_tag, dst_host, port,
    )
    .await;

    Ok(())
}

// ── WebSocket connect attempt ─────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn try_ws_connect(
    target_ip: Ipv4Addr,
    domains: &[String; 2],
    dc_key: &DcKey,
    label: &str,
    dc: u8,
    media_tag: &str,
    dst_host: &str,
    port: u16,
    config: &Config,
    tls: &Arc<ClientConfig>,
    pool: &Arc<WsPool>,
    stats: &Stats,
    ws_blacklist: &Arc<Mutex<HashSet<DcKey>>>,
    dc_fail_until: &Arc<Mutex<HashMap<DcKey, Instant>>>,
) -> Option<TlsStream> {
    // Pool first
    if let Some(stream) = pool
        .get(*dc_key, target_ip, domains, config, Arc::clone(tls))
        .await
    {
        stats.pool_hits.fetch_add(1, Relaxed);
        info!(
            "[{}] DC{}{} ({}:{}) -> pool hit via {}",
            label, dc, media_tag, dst_host, port, target_ip
        );
        return Some(stream);
    }
    stats.pool_misses.fetch_add(1, Relaxed);

    // Direct connect
    let mut all_redirects = true;
    let mut any_redirect = false;

    for domain in domains {
        info!(
            "[{}] DC{}{} -> wss://{}/apiws via {}",
            label, dc, media_tag, domain, target_ip
        );
        match websocket::connect(target_ip, domain, Arc::clone(tls), config.connect_timeout).await {
            Ok(stream) => {
                all_redirects = false;
                return Some(stream);
            }
            Err(e) if e.is_redirect() => {
                stats.ws_errors.fetch_add(1, Relaxed);
                any_redirect = true;
                warn!(
                    "[{}] DC{}{} redirect from {} → {}",
                    label, dc, media_tag, domain,
                    e.redirect_location().unwrap_or("?")
                );
                continue;
            }
            Err(e) => {
                stats.ws_errors.fetch_add(1, Relaxed);
                all_redirects = false;
                warn!("[{}] DC{}{} WS failed: {}", label, dc, media_tag, e);
                break;
            }
        }
    }

    if any_redirect && all_redirects {
        ws_blacklist.lock().await.insert(*dc_key);
        warn!("[{}] DC{}{} blacklisted (all 302)", label, dc, media_tag);
    } else {
        let until = Instant::now() + Duration::from_secs(COOLDOWN_SECS);
        dc_fail_until.lock().await.insert(*dc_key, until);
        info!("[{}] DC{}{} WS cooldown for {}s", label, dc, media_tag, COOLDOWN_SECS);
    }

    None
}

// ── DC resolution ─────────────────────────────────────────────────────────────

fn resolve_dc(ip: Ipv4Addr, init: &[u8; 64], config: &Config) -> (Option<u8>, bool, Vec<u8>, bool) {
    if let Some((dc, is_media)) = extract_dc(init) {
        if config.dc_ip(dc).is_some() {
            return (Some(dc), is_media, init.to_vec(), false);
        }
    }
    if let Some((dc, is_media)) = dc_from_ip(ip) {
        if config.dc_ip(dc).is_some() {
            let mut patched = init.to_vec();
            patch_dc(&mut patched, dc, is_media);
            return (Some(dc), is_media, patched, true);
        }
    }
    (None, false, init.to_vec(), false)
}

// ── TCP <-> WebSocket bridge ──────────────────────────────────────────────────

use tokio::io::{ReadHalf, WriteHalf};

async fn bridge_ws(
    tcp_read: OwnedReadHalf,
    tcp_write: OwnedWriteHalf,
    mut ws_read: ReadHalf<TlsStream>,
    mut ws_write: WriteHalf<TlsStream>,
    mut splitter: Option<MsgSplitter>,
    label: String,
    stats: Arc<Stats>,
    dc: u8,
    media_tag: &'static str,
    dst: String,
    port: u16,
) {
    let start = Instant::now();

    // Channel to send pong payloads from WS reader task to WS writer task
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);

    let label_up = label.clone();
    let stats_up = Arc::clone(&stats);

    // Task: TCP → WebSocket
    let t_up = tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        let mut bytes = 0u64;
        let mut tcp_read = tcp_read;

        loop {
            // Drain any pending pongs before reading next chunk
            while let Ok(payload) = pong_rx.try_recv() {
                let frame = build_frame(0xA, &payload, true); // OP_PONG
                if ws_write.write_all(&frame).await.is_err() {
                    return bytes;
                }
            }

            let n = match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &buf[..n];
            bytes += n as u64;
            stats_up.bytes_up.fetch_add(n as u64, Relaxed);

            let result = if let Some(ref mut sp) = splitter {
                let parts = sp.split(chunk);
                if parts.is_empty() {
                    Ok(()) // still buffering
                } else if parts.len() == 1 {
                    send_frame(&mut ws_write, &parts[0]).await
                } else {
                    send_frames(&mut ws_write, &parts).await
                }
            } else {
                send_frame(&mut ws_write, chunk).await
            };

            if let Err(e) = result {
                debug!("[{}] tcp->ws: {}", label_up, e);
                break;
            }
        }

        // Flush remaining splitter buffer
        if let Some(mut sp) = splitter {
            if let Some(remainder) = sp.flush() {
                let _ = send_frame(&mut ws_write, &remainder).await;
            }
        }
        let _ = send_close(&mut ws_write).await;
        bytes
    });

    let label_dn = label.clone();
    let stats_dn = Arc::clone(&stats);

    // Task: WebSocket → TCP
    let t_dn = tokio::spawn(async move {
        let mut bytes = 0u64;
        let mut tcp_write = tcp_write;

        loop {
            match recv_frame(&mut ws_read).await {
                Ok(Some(WsFrame::Data(data))) => {
                    bytes += data.len() as u64;
                    stats_dn.bytes_down.fetch_add(data.len() as u64, Relaxed);
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Some(WsFrame::Ping(payload))) => {
                    let _ = pong_tx.try_send(payload);
                }
                Ok(Some(WsFrame::Close)) | Ok(None) => break,
                Err(e) => {
                    debug!("[{}] ws->tcp: {}", label_dn, e);
                    break;
                }
            }
        }
        let _ = tcp_write.flush().await;
        bytes
    });

    // Wait for the first direction to finish
    let (up_bytes, dn_bytes) = tokio::select! {
        r = t_up => (r.unwrap_or(0), 0),
        r = t_dn => (0, r.unwrap_or(0)),
    };

    info!(
        "[{}] DC{}{} ({}:{}) closed: ^{} v{} in {:.1}s",
        label, dc, media_tag, dst, port,
        human_bytes(up_bytes),
        human_bytes(dn_bytes),
        start.elapsed().as_secs_f64()
    );
}

// ── TCP fallback ──────────────────────────────────────────────────────────────

async fn tcp_fallback(
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    dst: &str,
    port: u16,
    init: &[u8],
    label: &str,
    stats: &Stats,
    dc: Option<u8>,
    is_media: bool,
) {
    let remote = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:{}", dst, port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            warn!("[{}] TCP fallback connect to {}:{} failed", label, dst, port);
            return;
        }
    };
    let _ = remote.set_nodelay(true);
    stats.tcp_fallback.fetch_add(1, Relaxed);

    let dc_tag = match dc {
        Some(d) => format!("DC{}{}", d, if is_media { "m" } else { "" }),
        None => "DC?".to_string(),
    };

    let (mut rr, mut rw) = remote.into_split();

    if rw.write_all(init).await.is_err() {
        warn!("[{}] {} TCP fallback: failed to send init", label, dc_tag);
        return;
    }

    let t1 = tokio::spawn(async move { pipe_drain(reader, rw).await });
    let t2 = tokio::spawn(async move { pipe_drain(rr, writer).await });
    let _ = tokio::join!(t1, t2);

    info!("[{}] {} TCP fallback closed", label, dc_tag);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn pipe_drain(
    mut src: impl AsyncRead + Unpin + Send + 'static,
    mut dst: impl AsyncWrite + Unpin + Send + 'static,
) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = dst.flush().await;
}

fn socks5_reply(status: u8) -> [u8; 10] {
    let mut r = [0u8; 10];
    r[0] = 0x05;
    r[1] = status;
    r[3] = 0x01; // IPv4 BND.ADDR type
    r
}

fn is_http_header(data: &[u8]) -> bool {
    data.starts_with(b"POST ")
        || data.starts_with(b"GET ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
}

async fn timeout<F, T>(fut: F, secs: u64) -> Result<T, tokio::time::error::Elapsed>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(Duration::from_secs(secs), fut).await
}
