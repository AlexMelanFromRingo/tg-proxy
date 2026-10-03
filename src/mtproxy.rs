//! MTProto-proxy front-end (what `tg://proxy?...` links point at).
//!
//! The client speaks obfuscated2 keyed with our secret, optionally inside a fake
//! TLS 1.3 handshake. We learn the target datacenter from the (decrypted) init
//! packet, open the best route to it, and re-encrypt the stream with fresh keys.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::bridge::{bridge_tcp, bridge_ws, SessionInfo, Splitting, UpPath};
use crate::client::{ClientReader, ClientWriter};
use crate::crypto::{build_crypto, generate_relay_init, normalize_dc, try_handshake, MsgSplitter, HANDSHAKE_LEN};
use crate::fake_tls::{
    build_server_hello, proxy_to_masking_domain, unix_now, verify_client_hello, FakeTlsReader, FakeTlsWriter,
    ReplayCache, TLS_RECORD_HANDSHAKE,
};
use crate::route::{DcKey, Request, Route, Router};
use crate::websocket::tune_socket;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
/// A ClientHello is a few hundred bytes; refuse absurd record lengths.
const MAX_HELLO_RECORD: usize = 16 * 1024 + 512;
const MAX_PROXY_HEADER: usize = 108;

pub async fn run(router: Arc<Router>, listener: TcpListener) {
    let replay = Arc::new(ReplayCache::default());
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                warn!("MTProto accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        tune_socket(&sock, router.cfg.buffer_size);
        let (router, replay) = (router.clone(), replay.clone());
        tokio::spawn(async move { handle_client(sock, peer.to_string(), router, replay).await });
    }
}

async fn read_byte(rd: &mut OwnedReadHalf) -> Option<u8> {
    let mut b = [0u8; 1];
    match timeout(HANDSHAKE_TIMEOUT, rd.read_exact(&mut b)).await {
        Ok(Ok(_)) => Some(b[0]),
        _ => None,
    }
}

/// PROXY protocol v1: `PROXY TCP4 <src> <dst> <sport> <dport>\r\n`.
/// Returns the client's real `ip:port` when present.
async fn read_proxy_header(rd: &mut OwnedReadHalf) -> Result<Option<String>, ()> {
    let mut line = Vec::with_capacity(64);
    // A PROXY header always starts with "PROXY ": anything else is rejected at
    // once rather than after waiting for a newline that may never come.
    for &expected in b"PROXY " {
        let b = read_byte(rd).await.ok_or(())?;
        if b != expected {
            debug!("expected a PROXY header, got byte 0x{:02X}", b);
            return Err(());
        }
        line.push(b);
    }
    loop {
        let b = read_byte(rd).await.ok_or(())?;
        if b == b'\n' {
            break;
        }
        line.push(b);
        if line.len() > MAX_PROXY_HEADER {
            return Err(());
        }
    }
    let text = String::from_utf8_lossy(&line);
    let text = text.trim();
    if !text.starts_with("PROXY ") {
        debug!("expected a PROXY header, got {:?}", &text[..text.len().min(40)]);
        return Err(());
    }
    let parts: Vec<&str> = text.split_whitespace().collect();
    Ok((parts.len() >= 6).then(|| format!("{}:{}", parts[2], parts[4])))
}

/// Swallow whatever a failed handshake sends, so a prober cannot tell a bad
/// secret from a dead end by how quickly we hang up.
async fn drain(mut r: ClientReader) {
    let mut buf = [0u8; 4096];
    let _ = timeout(DRAIN_TIMEOUT, async { while matches!(r.read(&mut buf).await, Ok(n) if n > 0) {} }).await;
}

async fn handle_client(sock: TcpStream, mut label: String, router: Arc<Router>, replay: Arc<ReplayCache>) {
    let _active = router.stats.enter();
    let cfg = router.cfg.clone();
    let (mut rd, mut wr) = sock.into_split();

    if cfg.proxy_protocol {
        match read_proxy_header(&mut rd).await {
            Ok(Some(real)) => label = real,
            Ok(None) => {}
            Err(()) => {
                debug!("[{}] bad or missing PROXY header", label);
                return;
            }
        }
    }

    let Some(first) = read_byte(&mut rd).await else {
        debug!("[{}] client disconnected before the handshake", label);
        return;
    };
    let masking = &cfg.fake_tls_domain;

    let mut init = [0u8; HANDSHAKE_LEN];
    let (creader, cwriter) = if !masking.is_empty() && first == TLS_RECORD_HANDSHAKE {
        let mut rest = [0u8; 4];
        if timeout(HANDSHAKE_TIMEOUT, rd.read_exact(&mut rest)).await.map_or(true, |r| r.is_err()) {
            debug!("[{}] incomplete TLS record header", label);
            return;
        }
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if len > MAX_HELLO_RECORD {
            debug!("[{}] oversized TLS record ({} bytes) -> masking", label, len);
            let head = [first, rest[0], rest[1], rest[2], rest[3]];
            proxy_to_masking_domain(rd, wr, &head, &cfg, &label, &router.stats).await;
            return;
        }
        let mut hello = vec![first];
        hello.extend_from_slice(&rest);
        hello.resize(5 + len, 0);
        if timeout(HANDSHAKE_TIMEOUT, rd.read_exact(&mut hello[5..])).await.map_or(true, |r| r.is_err()) {
            debug!("[{}] incomplete TLS record body", label);
            return;
        }

        let verified =
            verify_client_hello(&hello, &cfg.secret, unix_now()).filter(|h| replay.check_and_insert(h.random));
        let Some(ch) = verified else {
            debug!("[{}] fake TLS verification failed -> masking", label);
            proxy_to_masking_domain(rd, wr, &hello, &cfg, &label, &router.stats).await;
            return;
        };
        debug!("[{}] fake TLS handshake ok (ts={})", label, ch.timestamp);
        if wr.write_all(&build_server_hello(&cfg.secret, &ch.random, &ch.session_id)).await.is_err() {
            return;
        }
        let mut r = ClientReader::Tls(FakeTlsReader::new(rd));
        let w = ClientWriter::Tls(FakeTlsWriter::new(wr));
        if timeout(HANDSHAKE_TIMEOUT, r.read_exact(&mut init)).await.map_or(true, |x| x.is_err()) {
            debug!("[{}] incomplete obfuscated2 init inside TLS", label);
            return;
        }
        (r, w)
    } else if !masking.is_empty() {
        // Not TLS at all: answer the way a plain web server on :443 would.
        debug!("[{}] non-TLS byte 0x{:02X} -> HTTP redirect", label, first);
        let resp = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{masking}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = wr.write_all(resp.as_bytes()).await;
        let _ = wr.shutdown().await;
        let mut sink = [0u8; 1024];
        let _ = timeout(Duration::from_secs(2), async { while matches!(rd.read(&mut sink).await, Ok(n) if n > 0) {} })
            .await;
        return;
    } else {
        init[0] = first;
        if timeout(HANDSHAKE_TIMEOUT, rd.read_exact(&mut init[1..])).await.map_or(true, |r| r.is_err()) {
            debug!("[{}] client disconnected before the handshake", label);
            return;
        }
        (ClientReader::Plain(rd), ClientWriter::Plain(wr))
    };

    let Some(hs) = try_handshake(&init, &cfg.secret) else {
        router.stats.bad.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        warn!("[{}] bad handshake (wrong secret or protocol)", label);
        drain(creader).await;
        return;
    };

    let (dc, media, test) = normalize_dc(hs.dc_raw, cfg.force_test_dc);
    if hs.dc_raw.unsigned_abs() >= 10000 {
        info!("[{}] test DC{} -> DC{}", label, hs.dc_raw.unsigned_abs(), dc);
    }
    let dc_idx = if media { -(dc as i16) } else { dc as i16 };
    debug!("[{}] handshake ok: DC{}{} proto=0x{:08X}", label, dc, if media { " media" } else { "" }, hs.proto);

    let relay_init = generate_relay_init(hs.proto, dc_idx);
    let (up, down) = build_crypto(&hs, &cfg.secret, &relay_init);

    let req = Request { dc, media, test, label: &label, orig_dst: None };
    let Some(route) = router.connect(&req).await else {
        return;
    };
    let session =
        SessionInfo { label: label.clone(), tag: DcKey { dc, media, test }.to_string(), stats: router.stats.clone() };

    match route {
        Route::Ws { mut conn, framed, .. } => {
            if let Err(e) = conn.send(&relay_init).await {
                warn!("[{}] failed to send the init frame: {}", label, e);
                return;
            }
            let splitting = framed.then(|| Splitting { splitter: MsgSplitter::new(hs.proto), decryptor: None });
            bridge_ws(creader, cwriter, conn, UpPath::Reencrypt(Box::new(up)), Some(down), splitting, session).await;
        }
        Route::Tcp(mut remote) => {
            if let Err(e) = remote.write_all(&relay_init).await {
                warn!("[{}] failed to send the init packet: {}", label, e);
                return;
            }
            bridge_tcp(creader, cwriter, remote, UpPath::Reencrypt(Box::new(up)), Some(down), session).await;
        }
    }
}
