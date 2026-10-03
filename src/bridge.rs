//! Pumping bytes between a client connection and the chosen upstream route.
//!
//! Each direction runs in its own task so a slow reader on one side can never
//! stall the other. The first direction to finish ends the session.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cipher::StreamCipher;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::info;

use crate::client::{ClientReader, ClientWriter};
use crate::crypto::{Aes256Ctr, DownCrypto, MsgSplitter, UpCrypto};
use crate::stats::{human_bytes, Stats};
use crate::websocket::{WsConn, WsMsg};

const RECV_BUF: usize = 65536;

/// How client→upstream bytes are transformed.
pub enum UpPath {
    /// MTProto-proxy mode: decrypt with the client's key, re-encrypt for Telegram.
    Reencrypt(Box<UpCrypto>),
    /// SOCKS5 mode: bytes travel unchanged.
    Verbatim,
}

/// Packet-boundary splitting for WebSocket gateways (one packet per frame).
pub struct Splitting {
    pub splitter: MsgSplitter,
    /// SOCKS5 mode only: decrypts the client's stream just to read the length
    /// prefixes (in MTProto mode the plaintext is already at hand).
    pub decryptor: Option<Aes256Ctr>,
}

pub struct SessionInfo {
    pub label: String,
    /// e.g. `DC2m`
    pub tag: String,
    pub stats: Arc<Stats>,
}

fn io_reason(what: &str, e: &io::Error) -> String {
    format!("{what}: {:?}", e.kind())
}

fn finish_log(info: &SessionInfo, kind: &str, reason: &str, up: u64, down: u64, start: Instant) {
    info!(
        "[{}] {} {} session closed ({}): ^{} v{} in {:.1}s",
        info.label,
        info.tag,
        kind,
        reason,
        human_bytes(up),
        human_bytes(down),
        start.elapsed().as_secs_f64()
    );
}

/// Client ⇄ WebSocket.
pub async fn bridge_ws(
    mut client_r: ClientReader,
    mut client_w: ClientWriter,
    ws: WsConn,
    mut up: UpPath,
    mut down: Option<DownCrypto>,
    mut splitting: Option<Splitting>,
    info: SessionInfo,
) {
    let start = Instant::now();
    let (mut ws_r, ws_w) = ws.split();
    let ws_w = Arc::new(Mutex::new(ws_w));
    let up_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes = Arc::new(AtomicU64::new(0));

    let mut up_task = {
        let (ws_w, up_bytes, stats) = (ws_w.clone(), up_bytes.clone(), info.stats.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            loop {
                let n = match client_r.read(&mut buf).await {
                    Ok(0) => {
                        if let Some(tail) = splitting.as_mut().and_then(|s| s.splitter.flush()) {
                            let _ = ws_w.lock().await.send(&tail).await;
                        }
                        return "client closed".to_string();
                    }
                    Ok(n) => n,
                    Err(e) => return io_reason("client read", &e),
                };
                up_bytes.fetch_add(n as u64, Relaxed);
                stats.bytes_up.fetch_add(n as u64, Relaxed);
                let chunk = &mut buf[..n];

                // Plaintext is only needed to find packet boundaries.
                let mut plain: Option<Vec<u8>> = None;
                match &mut up {
                    UpPath::Reencrypt(c) => {
                        c.decrypt_client(chunk);
                        if splitting.is_some() {
                            plain = Some(chunk.to_vec());
                        }
                        c.encrypt_upstream(chunk);
                    }
                    UpPath::Verbatim => {
                        if let Some(d) = splitting.as_mut().and_then(|s| s.decryptor.as_mut()) {
                            let mut p = chunk.to_vec();
                            d.apply_keystream(&mut p);
                            plain = Some(p);
                        }
                    }
                }

                let res = match (splitting.as_mut(), plain) {
                    (Some(s), Some(plain)) => {
                        let parts = s.splitter.split(&plain, chunk);
                        match parts.len() {
                            0 => Ok(()),
                            1 => ws_w.lock().await.send(&parts[0]).await,
                            _ => ws_w.lock().await.send_batch(&parts).await,
                        }
                    }
                    _ => ws_w.lock().await.send(chunk).await,
                };
                if let Err(e) = res {
                    return io_reason("upstream write", &e);
                }
            }
        })
    };

    let mut down_task = {
        let (ws_w, down_bytes, stats) = (ws_w.clone(), down_bytes.clone(), info.stats.clone());
        tokio::spawn(async move {
            let reason = loop {
                match ws_r.recv().await {
                    Ok(Some(WsMsg::Data(mut data))) => {
                        down_bytes.fetch_add(data.len() as u64, Relaxed);
                        stats.bytes_down.fetch_add(data.len() as u64, Relaxed);
                        if let Some(d) = down.as_mut() {
                            d.reencrypt(&mut data);
                        }
                        if let Err(e) = client_w.write_all(&data).await {
                            break io_reason("client write", &e);
                        }
                    }
                    Ok(Some(WsMsg::Ping(p))) => {
                        if let Err(e) = ws_w.lock().await.pong(&p).await {
                            break io_reason("pong", &e);
                        }
                    }
                    Ok(Some(WsMsg::Close(code))) => break format!("upstream closed ({:?})", code),
                    Ok(None) => break "upstream closed".to_string(),
                    Err(e) => break io_reason("upstream read", &e),
                }
            };
            client_w.shutdown().await;
            reason
        })
    };

    let reason = tokio::select! {
        r = &mut up_task => { down_task.abort(); let _ = down_task.await; r.unwrap_or_default() }
        r = &mut down_task => { up_task.abort(); let _ = up_task.await; r.unwrap_or_default() }
    };

    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        ws_w.lock().await.close().await;
    })
    .await;
    finish_log(&info, "WS", &reason, up_bytes.load(Relaxed), down_bytes.load(Relaxed), start);
}

/// Client ⇄ raw TCP (fallback route).
pub async fn bridge_tcp(
    mut client_r: ClientReader,
    mut client_w: ClientWriter,
    remote: TcpStream,
    mut up: UpPath,
    mut down: Option<DownCrypto>,
    info: SessionInfo,
) {
    let start = Instant::now();
    let (mut remote_r, mut remote_w) = remote.into_split();
    let up_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes = Arc::new(AtomicU64::new(0));

    let mut up_task = {
        let (up_bytes, stats) = (up_bytes.clone(), info.stats.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            loop {
                let n = match client_r.read(&mut buf).await {
                    Ok(0) => {
                        let _ = remote_w.shutdown().await;
                        return "client closed".to_string();
                    }
                    Ok(n) => n,
                    Err(e) => return io_reason("client read", &e),
                };
                up_bytes.fetch_add(n as u64, Relaxed);
                stats.bytes_up.fetch_add(n as u64, Relaxed);
                if let UpPath::Reencrypt(c) = &mut up {
                    c.decrypt_client(&mut buf[..n]);
                    c.encrypt_upstream(&mut buf[..n]);
                }
                if let Err(e) = remote_w.write_all(&buf[..n]).await {
                    return io_reason("upstream write", &e);
                }
            }
        })
    };

    let mut down_task = {
        let (down_bytes, stats) = (down_bytes.clone(), info.stats.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            let reason = loop {
                let n = match remote_r.read(&mut buf).await {
                    Ok(0) => break "upstream closed".to_string(),
                    Ok(n) => n,
                    Err(e) => break io_reason("upstream read", &e),
                };
                down_bytes.fetch_add(n as u64, Relaxed);
                stats.bytes_down.fetch_add(n as u64, Relaxed);
                if let Some(d) = down.as_mut() {
                    d.reencrypt(&mut buf[..n]);
                }
                if let Err(e) = client_w.write_all(&buf[..n]).await {
                    break io_reason("client write", &e);
                }
            };
            client_w.shutdown().await;
            reason
        })
    };

    let reason = tokio::select! {
        r = &mut up_task => { down_task.abort(); let _ = down_task.await; r.unwrap_or_default() }
        r = &mut down_task => { up_task.abort(); let _ = up_task.await; r.unwrap_or_default() }
    };
    finish_log(&info, "TCP", &reason, up_bytes.load(Relaxed), down_bytes.load(Relaxed), start);
}
