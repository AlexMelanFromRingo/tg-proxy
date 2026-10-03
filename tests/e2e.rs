#![allow(clippy::field_reassign_with_default, clippy::manual_range_patterns)]
//! End-to-end tests: a simulated Telegram client talks to the real proxy code,
//! which talks to mock Telegram infrastructure (WS gateway with TLS, raw DC,
//! Cloudflare-Worker-style relay, SOCKS5 upstream). Nothing leaves the machine
//! except the `#[ignore]`d live test at the bottom.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cipher::StreamCipher;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{RootCertStore, ServerConfig};
use tg_proxy::config::Settings;
use tg_proxy::crypto::{
    client_init_with_secret, generate_relay_init, upstream_ciphers, Aes256Ctr, PROTO_ABRIDGED, PROTO_INTERMEDIATE,
};
use tg_proxy::fake_tls::{build_client_hello, unix_now, verify_server_hello, wrap_tls_records, FakeTlsReader};
use tg_proxy::route::Router;
use tg_proxy::stats::Stats;
use tg_proxy::websocket::{self, ConnectOpts, Target, TlsConfigs};
use tg_proxy::{mtproxy, socks5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

const SECRET: [u8; 16] = [0x11; 16];
const STEP: Duration = Duration::from_secs(10);

/// Bound every await so a bug fails the test instead of hanging it.
async fn t<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(30), f).await.expect("test timed out")
}

fn lo() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

// ── TLS test PKI ──────────────────────────────────────────────────────────────

struct Pki {
    roots: Arc<RootCertStore>,
    server: Arc<ServerConfig>,
}

fn pki(names: &[&str]) -> Pki {
    let ck = rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    let cert = ck.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let server = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert], key.into()).unwrap();
    Pki { roots: Arc::new(roots), server: Arc::new(server) }
}

/// Same names as the real gateway certificate (`*.web.telegram.org`).
fn gateway_pki() -> Pki {
    pki(&["*.web.telegram.org", "web.telegram.org"])
}

// ── WebSocket plumbing for the mock servers ───────────────────────────────────

fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80 | opcode];
    let len = payload.len();
    if len < 126 {
        f.push(len as u8);
    } else if len < 65536 {
        f.push(126);
        f.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        f.push(127);
        f.extend_from_slice(&(len as u64).to_be_bytes());
    }
    f.extend_from_slice(payload);
    f
}

/// Parse one (masked) client frame from `buf`: `(bytes consumed, opcode, payload)`.
fn parse_client_frame(buf: &[u8]) -> Option<(usize, u8, Vec<u8>)> {
    if buf.len() < 2 {
        return None;
    }
    let opcode = buf[0] & 0x0F;
    let masked = buf[1] & 0x80 != 0;
    let mut len = (buf[1] & 0x7F) as usize;
    let mut off = 2;
    if len == 126 {
        if buf.len() < 4 {
            return None;
        }
        len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        off = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return None;
        }
        len = u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize;
        off = 10;
    }
    let mask_len = if masked { 4 } else { 0 };
    if buf.len() < off + mask_len + len {
        return None;
    }
    let mut payload = buf[off + mask_len..off + mask_len + len].to_vec();
    if masked {
        let key = [buf[off], buf[off + 1], buf[off + 2], buf[off + 3]];
        websocket::mask_in_place(&mut payload, key);
    }
    Some((off + mask_len + len, opcode, payload))
}

/// Next data message from the client; `None` on close/EOF.
async fn read_ws_msg<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        if let Some((used, opcode, payload)) = parse_client_frame(buf) {
            buf.drain(..used);
            match opcode {
                0 | 1 | 2 => return Some(payload),
                8 => return None,
                _ => continue,
            }
        }
        let mut tmp = [0u8; 16384];
        let n = r.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Read an HTTP request head; returns it and any bytes already received after it.
async fn read_http_head<R: AsyncRead + Unpin>(r: &mut R) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Some((String::from_utf8_lossy(&buf).into_owned(), rest));
        }
        let mut tmp = [0u8; 2048];
        let n = r.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

const SWITCH: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

fn xor_ff(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b ^ 0xFF).collect()
}

// ── Mock Telegram WS gateway (TLS) ────────────────────────────────────────────

#[derive(Default, Clone)]
struct ConnRec {
    head: String,
    sni: Option<String>,
    init: Option<[u8; 64]>,
    frames: Vec<Vec<u8>>,
}

type Rec = Arc<Mutex<Vec<ConnRec>>>;

#[derive(Clone, Default)]
struct GatewayOpts {
    /// Drop the TLS handshake of connections whose SNI starts with this prefix.
    cut_sni_prefix: Option<&'static str>,
    /// Close connections that stay idle this long after the upgrade.
    idle_close: Option<Duration>,
}

struct Gateway {
    addr: SocketAddr,
    rec: Rec,
    cut: Arc<Mutex<usize>>,
}

async fn spawn_gateway(pki: &Pki, opts: GatewayOpts) -> Gateway {
    let listener = TcpListener::bind((lo(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rec: Rec = Arc::default();
    let cut = Arc::new(Mutex::new(0usize));
    let server = pki.server.clone();
    let (rec2, cut2) = (rec.clone(), cut.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let (server, rec, cut, opts) = (server.clone(), rec2.clone(), cut2.clone(), opts.clone());
            tokio::spawn(async move {
                let start =
                    tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp).await.ok()?;
                let sni = start.client_hello().server_name().map(str::to_string);
                if let (Some(prefix), Some(s)) = (opts.cut_sni_prefix, &sni) {
                    if s.starts_with(prefix) {
                        *cut.lock().unwrap() += 1;
                        return None; // dropping `start` closes the socket mid-handshake
                    }
                }
                let tls = start.into_stream(server).await.ok()?;
                serve_gateway(tls, rec, sni, opts.idle_close).await;
                Some(())
            });
        }
    });
    Gateway { addr, rec, cut }
}

async fn serve_gateway<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    rec: Rec,
    sni: Option<String>,
    idle_close: Option<Duration>,
) {
    let Some((head, mut buf)) = read_http_head(&mut s).await else { return };
    if s.write_all(SWITCH).await.is_err() {
        return;
    }
    let idx = {
        let mut r = rec.lock().unwrap();
        r.push(ConnRec { head, sni, ..Default::default() });
        r.len() - 1
    };
    let mut ciphers: Option<(Aes256Ctr, Aes256Ctr)> = None;
    loop {
        let msg = match (idle_close, ciphers.is_none()) {
            (Some(d), true) => match tokio::time::timeout(d, read_ws_msg(&mut s, &mut buf)).await {
                Ok(m) => m,
                Err(_) => return, // idle too long: hang up
            },
            _ => read_ws_msg(&mut s, &mut buf).await,
        };
        let Some(msg) = msg else { return };
        match &mut ciphers {
            None => {
                let init: [u8; 64] = msg.try_into().expect("first message is the 64-byte init");
                ciphers = Some(upstream_ciphers(&init));
                rec.lock().unwrap()[idx].init = Some(init);
            }
            Some((dec, enc)) => {
                let mut plain = msg;
                dec.apply_keystream(&mut plain);
                rec.lock().unwrap()[idx].frames.push(plain.clone());
                let mut reply = xor_ff(&plain);
                enc.apply_keystream(&mut reply);
                if s.write_all(&ws_frame(2, &reply)).await.is_err() {
                    return;
                }
            }
        }
    }
}

// ── Mock datacenter (raw TCP, obfuscated2) ────────────────────────────────────

#[derive(Default, Clone)]
struct DcRec {
    init: Option<[u8; 64]>,
    plain: Vec<u8>,
}

async fn serve_dc<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, rec: Arc<Mutex<Vec<DcRec>>>) {
    let mut init = [0u8; 64];
    if s.read_exact(&mut init).await.is_err() {
        return;
    }
    let idx = {
        let mut r = rec.lock().unwrap();
        r.push(DcRec { init: Some(init), plain: Vec::new() });
        r.len() - 1
    };
    let (mut dec, mut enc) = upstream_ciphers(&init);
    let mut buf = [0u8; 8192];
    loop {
        let n = match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let mut plain = buf[..n].to_vec();
        dec.apply_keystream(&mut plain);
        rec.lock().unwrap()[idx].plain.extend_from_slice(&plain);
        let mut reply = xor_ff(&plain);
        enc.apply_keystream(&mut reply);
        if s.write_all(&reply).await.is_err() {
            return;
        }
    }
}

async fn spawn_dc() -> (SocketAddr, Arc<Mutex<Vec<DcRec>>>) {
    let l = TcpListener::bind((lo(), 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    let rec: Arc<Mutex<Vec<DcRec>>> = Arc::default();
    let rec2 = rec.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(serve_dc(s, rec2.clone()));
        }
    });
    (addr, rec)
}

// ── Mock Cloudflare Worker: WS in, raw TCP out ────────────────────────────────

async fn spawn_worker(dc_addr: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind((lo(), 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    let heads: Arc<Mutex<Vec<String>>> = Arc::default();
    let heads2 = heads.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let heads = heads2.clone();
            tokio::spawn(async move {
                let (head, mut buf) = read_http_head(&mut s).await?;
                heads.lock().unwrap().push(head);
                s.write_all(SWITCH).await.ok()?;
                let tcp = TcpStream::connect(dc_addr).await.ok()?;
                let (mut tr, mut tw) = tcp.into_split();
                let (mut sr, mut sw) = s.into_split();
                let up = tokio::spawn(async move {
                    while let Some(msg) = read_ws_msg(&mut sr, &mut buf).await {
                        if tw.write_all(&msg).await.is_err() {
                            break;
                        }
                    }
                });
                let mut b = [0u8; 8192];
                loop {
                    let n = tr.read(&mut b).await.ok()?;
                    if n == 0 {
                        break;
                    }
                    sw.write_all(&ws_frame(2, &b[..n])).await.ok()?;
                }
                up.abort();
                Some(())
            });
        }
    });
    (addr, heads)
}

// ── Mock SOCKS5 server (the `--upstream-socks5` peer) ─────────────────────────

/// Accepts SOCKS5 CONNECTs, records the requested `(host, port)`, and splices the
/// connection to `backend` regardless of what was asked for.
async fn spawn_socks_upstream(backend: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<(String, u16)>>>) {
    let l = TcpListener::bind((lo(), 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<(String, u16)>>> = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut h = [0u8; 2];
                s.read_exact(&mut h).await.ok()?;
                let mut methods = vec![0u8; h[1] as usize];
                s.read_exact(&mut methods).await.ok()?;
                s.write_all(&[5, 0]).await.ok()?;
                let mut r = [0u8; 4];
                s.read_exact(&mut r).await.ok()?;
                let host = match r[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        s.read_exact(&mut a).await.ok()?;
                        Ipv4Addr::from(a).to_string()
                    }
                    3 => {
                        let mut l = [0u8; 1];
                        s.read_exact(&mut l).await.ok()?;
                        let mut n = vec![0u8; l[0] as usize];
                        s.read_exact(&mut n).await.ok()?;
                        String::from_utf8(n).ok()?
                    }
                    _ => return None,
                };
                let mut p = [0u8; 2];
                s.read_exact(&mut p).await.ok()?;
                seen.lock().unwrap().push((host.clone(), u16::from_be_bytes(p)));
                let dest =
                    if host == "127.0.0.1" { SocketAddr::new(lo().into(), u16::from_be_bytes(p)) } else { backend };
                let mut backend = TcpStream::connect(dest).await.ok()?;
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok()?;
                tokio::io::copy_bidirectional(&mut s, &mut backend).await.ok()?;
                Some(())
            });
        }
    });
    (addr, seen)
}

/// Plain TCP echo server (stands in for "any website" behind the SOCKS5 upstream).
async fn spawn_echo() -> SocketAddr {
    let l = TcpListener::bind((lo(), 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || s.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

// ── Proxy under test ──────────────────────────────────────────────────────────

struct Proxy {
    mtproto: SocketAddr,
    socks: SocketAddr,
    router: Arc<Router>,
    stats: Arc<Stats>,
}

/// A port nothing listens on.
async fn dead_port() -> u16 {
    let l = TcpListener::bind((lo(), 0)).await.unwrap();
    l.local_addr().unwrap().port()
}

fn settings(gateway: Option<&Gateway>) -> Settings {
    let mut s = Settings::default();
    s.secret = SECRET;
    s.pool_size = 0;
    s.fallback_cfproxy = false;
    s.fronting_sni = String::new();
    s.connect_timeout = Duration::from_secs(3);
    s.dc_redirects = match gateway {
        Some(g) => {
            s.gateway_port = g.addr.port();
            [(2, lo())].into()
        }
        None => Default::default(),
    };
    s
}

async fn start_proxy(cfg: Settings, tls: TlsConfigs) -> Proxy {
    let cfg = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let router = Router::with_tls(cfg, stats.clone(), Arc::new(tls));
    let ml = TcpListener::bind((lo(), 0)).await.unwrap();
    let sl = TcpListener::bind((lo(), 0)).await.unwrap();
    let (mtproto, socks) = (ml.local_addr().unwrap(), sl.local_addr().unwrap());
    tokio::spawn(mtproxy::run(router.clone(), ml));
    tokio::spawn(socks5::run(router.clone(), sl));
    Proxy { mtproto, socks, router, stats }
}

fn tls_for(pki: &Pki) -> TlsConfigs {
    websocket::tls_configs_with_roots(pki.roots.clone()).unwrap()
}

// ── Simulated Telegram clients ────────────────────────────────────────────────

struct MtClient {
    r: OwnedReadHalf,
    w: OwnedWriteHalf,
    enc: Aes256Ctr,
    dec: Aes256Ctr,
}

impl MtClient {
    async fn connect(addr: SocketAddr, proto: u32, dc_idx: i16) -> Self {
        let (init, enc, dec) = client_init_with_secret(&SECRET, proto, dc_idx);
        let (r, mut w) = TcpStream::connect(addr).await.unwrap().into_split();
        w.write_all(&init).await.unwrap();
        Self { r, w, enc, dec }
    }

    async fn send(&mut self, data: &[u8]) {
        let mut d = data.to_vec();
        self.enc.apply_keystream(&mut d);
        self.w.write_all(&d).await.unwrap();
    }

    async fn recv_exact(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(STEP, self.r.read_exact(&mut buf))
            .await
            .expect("reply timed out")
            .expect("connection closed before the full reply");
        self.dec.apply_keystream(&mut buf);
        buf
    }
}

/// Three abridged-transport packets (one long-form) and their concatenation.
fn abridged_packets() -> (Vec<Vec<u8>>, Vec<u8>) {
    let p1 = [vec![3u8], vec![1u8; 12]].concat();
    let p2 = [vec![0x7Fu8, 40, 0, 0], vec![2u8; 160]].concat();
    let p3 = [vec![1u8], vec![3u8; 4]].concat();
    let all = [p1.clone(), p2.clone(), p3.clone()].concat();
    (vec![p1, p2, p3], all)
}

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

// ═════════════════════════════ MTProto mode ══════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mtproto_direct_ws_splits_packets_and_reencrypts() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let proxy = start_proxy(settings(Some(&gw)), tls_for(&pki)).await;

        let mut c = MtClient::connect(proxy.mtproto, PROTO_ABRIDGED, 2).await;
        let (packets, all) = abridged_packets();
        c.send(&all).await; // one TCP write holding three packets
        let reply = c.recv_exact(all.len()).await;
        assert_eq!(reply, xor_ff(&all), "replies come back decrypted for the client");

        let rec = gw.rec.lock().unwrap().clone();
        assert_eq!(rec.len(), 1);
        let conn = &rec[0];
        assert!(conn.head.starts_with("GET /apiws HTTP/1.1\r\n"), "{}", conn.head);
        assert!(conn.head.contains("Host: kws2.web.telegram.org\r\n"));
        assert_eq!(conn.sni.as_deref(), Some("kws2.web.telegram.org"));
        assert!(conn.init.is_some(), "the relay init is the first WS message");
        assert_eq!(conn.frames, packets, "one MTProto packet per WebSocket frame");
        assert_eq!(proxy.stats.ws.load(std::sync::atomic::Ordering::Relaxed), 1);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mtproto_fresh_keys_towards_telegram_and_media_host() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let proxy = start_proxy(settings(Some(&gw)), tls_for(&pki)).await;

        // A media connection (negative DC index) uses the "-1" host.
        let mut c = MtClient::connect(proxy.mtproto, PROTO_INTERMEDIATE, -2).await;
        let pkt = [8u32.to_le_bytes().to_vec(), vec![9u8; 8]].concat();
        c.send(&pkt).await;
        assert_eq!(c.recv_exact(pkt.len()).await, xor_ff(&pkt));
        let rec = gw.rec.lock().unwrap().clone();
        assert_eq!(rec[0].sni.as_deref(), Some("kws2-1.web.telegram.org"));
        assert_eq!(rec[0].frames, vec![pkt]);

        // The init forwarded to Telegram is NOT the client's: keys are fresh each time.
        let init1 = rec[0].init.unwrap();
        let mut c2 = MtClient::connect(proxy.mtproto, PROTO_INTERMEDIATE, -2).await;
        c2.send(&[8, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]).await;
        c2.recv_exact(12).await;
        let init2 = gw.rec.lock().unwrap()[1].init.unwrap();
        assert_ne!(init1, init2);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fronting_takes_over_when_the_plain_sni_is_cut() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts { cut_sni_prefix: Some("kws"), ..Default::default() }).await;
        let mut cfg = settings(Some(&gw));
        cfg.fronting_sni = "front.example".into();
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        let (_, all) = abridged_packets();
        let mut c = MtClient::connect(proxy.mtproto, PROTO_ABRIDGED, 2).await;
        c.send(&all).await;
        assert_eq!(c.recv_exact(all.len()).await, xor_ff(&all));

        let rec = gw.rec.lock().unwrap().clone();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].sni.as_deref(), Some("front.example"), "the wire shows the innocuous SNI");
        assert!(
            rec[0].head.contains("Host: kws2.web.telegram.org\r\n"),
            "…while Host still selects the real backend: {}",
            rec[0].head
        );
        assert!(proxy.router.connector.prefers_fronting(), "the working mode is remembered");
        assert_eq!(proxy.stats.fronting.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(*gw.cut.lock().unwrap(), 1, "one plain attempt was cut");

        // The next connection goes straight to the working mode: no new plain attempt.
        let mut c2 = MtClient::connect(proxy.mtproto, PROTO_ABRIDGED, 2).await;
        c2.send(&all).await;
        assert_eq!(c2.recv_exact(all.len()).await, xor_ff(&all));
        assert_eq!(*gw.cut.lock().unwrap(), 1, "fronting is tried first once it is known to work");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificate_must_match_even_when_fronting() {
    t(async {
        let good = gateway_pki();
        let evil = pki(&["evil.example"]);
        let gw_good = spawn_gateway(&good, GatewayOpts::default()).await;
        let gw_evil = spawn_gateway(&evil, GatewayOpts::default()).await;
        // Trust BOTH test CAs: the only thing left to reject the evil gateway is name pinning.
        let mut roots = RootCertStore::empty();
        roots.roots.extend(good.roots.roots.iter().cloned());
        roots.roots.extend(evil.roots.roots.iter().cloned());
        let tls = websocket::tls_configs_with_roots(Arc::new(roots)).unwrap();

        let opts = |gw: &Gateway, fronted: bool| {
            let mut o =
                ConnectOpts::new(Target::Addr(gw.addr), "kws2.web.telegram.org", "/apiws", Duration::from_secs(5));
            if fronted {
                o.sni = Some("front.example".into());
                o.fronted = true;
            }
            o
        };
        assert!(websocket::connect(&tls, &opts(&gw_good, true)).await.is_ok(), "valid for web.telegram.org");
        assert!(websocket::connect(&tls, &opts(&gw_good, false)).await.is_ok());
        assert!(
            websocket::connect(&tls, &opts(&gw_evil, true)).await.is_err(),
            "a certificate for another name must be rejected on a fronted connection"
        );
        assert!(websocket::connect(&tls, &opts(&gw_evil, false)).await.is_err());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_takes_over_when_direct_is_dead_and_for_dcs_without_a_gateway() {
    t(async {
        let (dc_addr, dc_rec) = spawn_dc().await;
        let (worker_addr, worker_heads) = spawn_worker(dc_addr).await;
        let pki = gateway_pki();
        let mut cfg = settings(None);
        cfg.dc_redirects = [(2, lo())].into();
        cfg.gateway_port = dead_port().await; // direct to DC2 is refused
        cfg.cfproxy_worker_domains = vec![worker_addr.to_string()];
        cfg.disable_secure = true; // the mock worker speaks plain WS
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        let (_, all) = abridged_packets();
        for (dc, table_ip) in [(2i16, "149.154.167.51"), (1, "149.154.175.50"), (5, "149.154.171.5")] {
            let before = dc_rec.lock().unwrap().len();
            let mut c = MtClient::connect(proxy.mtproto, PROTO_ABRIDGED, dc).await;
            c.send(&all).await;
            assert_eq!(c.recv_exact(all.len()).await, xor_ff(&all), "DC{dc}");

            let heads = worker_heads.lock().unwrap().clone();
            let head = heads.last().unwrap();
            assert!(head.starts_with(&format!("GET /apiws?dst={table_ip}&dc={dc} HTTP/1.1\r\n")), "DC{dc}: {head}");
            let dc_rec = dc_rec.lock().unwrap();
            assert_eq!(dc_rec.len(), before + 1);
            // A Worker is a raw TCP pipe: the DC sees the plain stream, not WS frames.
            assert_eq!(dc_rec.last().unwrap().plain, all, "DC{dc}: stream reaches the DC intact");
        }
        assert_eq!(proxy.stats.cf_worker.load(std::sync::atomic::Ordering::Relaxed), 3);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_route_closes_the_client_instead_of_hanging() {
    t(async {
        let pki = gateway_pki();
        let mut cfg = settings(None);
        cfg.dc_redirects = [(2, lo())].into();
        cfg.gateway_port = dead_port().await;
        // No worker, no CF, and DC 7 has no raw-TCP address either.
        let proxy = start_proxy(cfg, tls_for(&pki)).await;
        let mut c = MtClient::connect(proxy.mtproto, PROTO_ABRIDGED, 7).await;
        let mut b = [0u8; 16];
        let r = tokio::time::timeout(STEP, c.r.read(&mut b)).await.expect("must close promptly");
        assert!(matches!(r, Ok(0) | Err(_)));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_secret_is_counted_and_gets_no_answer() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let proxy = start_proxy(settings(Some(&gw)), tls_for(&pki)).await;

        let (init, _, _) = client_init_with_secret(&[0x99; 16], PROTO_ABRIDGED, 2);
        let mut s = TcpStream::connect(proxy.mtproto).await.unwrap();
        s.write_all(&init).await.unwrap();
        s.write_all(&[1, 2, 3]).await.unwrap();
        eventually("bad handshake counted", || proxy.stats.bad.load(std::sync::atomic::Ordering::Relaxed) == 1).await;
        let mut b = [0u8; 8];
        let silent = tokio::time::timeout(Duration::from_millis(300), s.read(&mut b)).await;
        assert!(silent.is_err(), "a prober gets silence, not an error");
        assert!(gw.rec.lock().unwrap().is_empty(), "nothing is forwarded to Telegram");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_header_is_required_when_enabled() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let mut cfg = settings(Some(&gw));
        cfg.proxy_protocol = true;
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        // Without the header the connection is dropped.
        let mut c = MtClient::connect(proxy.mtproto, PROTO_ABRIDGED, 2).await;
        let mut b = [0u8; 8];
        assert!(matches!(tokio::time::timeout(STEP, c.r.read(&mut b)).await, Ok(Ok(0)) | Ok(Err(_))));

        // With it, everything works.
        let (init, mut enc, mut dec) = client_init_with_secret(&SECRET, PROTO_ABRIDGED, 2);
        let mut s = TcpStream::connect(proxy.mtproto).await.unwrap();
        s.write_all(b"PROXY TCP4 203.0.113.9 192.0.2.1 51234 443\r\n").await.unwrap();
        s.write_all(&init).await.unwrap();
        let (_, all) = abridged_packets();
        let mut d = all.clone();
        enc.apply_keystream(&mut d);
        s.write_all(&d).await.unwrap();
        let mut reply = vec![0u8; all.len()];
        tokio::time::timeout(STEP, s.read_exact(&mut reply)).await.unwrap().unwrap();
        dec.apply_keystream(&mut reply);
        assert_eq!(reply, xor_ff(&all));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_serves_prewarmed_connections() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let mut cfg = settings(Some(&gw));
        cfg.pool_size = 2;
        let proxy = start_proxy(cfg, tls_for(&pki)).await;
        proxy.router.pool.warmup();
        // 1 DC × (plain + media) × 2 connections
        eventually("pool warmup", || {
            proxy.router.pool.idle_len((2, false)) == 2 && proxy.router.pool.idle_len((2, true)) == 2
        })
        .await;

        let (_, all) = abridged_packets();
        let mut c = MtClient::connect(proxy.mtproto, PROTO_ABRIDGED, 2).await;
        c.send(&all).await;
        assert_eq!(c.recv_exact(all.len()).await, xor_ff(&all));
        assert_eq!(proxy.stats.pool_hits.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(proxy.stats.pool_misses.load(std::sync::atomic::Ordering::Relaxed), 0);
        // The used connection (already open) carried the traffic.
        let used = gw.rec.lock().unwrap().iter().filter(|r| !r.frames.is_empty()).count();
        assert_eq!(used, 1);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_pooled_connections_are_skipped() {
    t(async {
        let pki = gateway_pki();
        let gw =
            spawn_gateway(&pki, GatewayOpts { idle_close: Some(Duration::from_millis(150)), ..Default::default() })
                .await;
        let mut cfg = settings(Some(&gw));
        cfg.pool_size = 1;
        let proxy = start_proxy(cfg, tls_for(&pki)).await;
        proxy.router.pool.warmup();
        eventually("pool warmup", || proxy.router.pool.idle_len((2, false)) == 1).await;
        tokio::time::sleep(Duration::from_millis(500)).await; // the gateway hangs up on idle ones

        let (_, all) = abridged_packets();
        let mut c = MtClient::connect(proxy.mtproto, PROTO_ABRIDGED, 2).await;
        c.send(&all).await;
        assert_eq!(c.recv_exact(all.len()).await, xor_ff(&all), "a fresh connection is made instead");
        assert_eq!(proxy.stats.pool_hits.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(proxy.stats.pool_misses.load(std::sync::atomic::Ordering::Relaxed), 1);
    })
    .await;
}

// ═══════════════════════════════ Fake TLS ════════════════════════════════════

/// Read the server's flight (ServerHello, CCS, one application record).
async fn read_server_flight(r: &mut OwnedReadHalf) -> Vec<u8> {
    let mut flight = Vec::new();
    for _ in 0..3 {
        let mut hdr = [0u8; 5];
        tokio::time::timeout(STEP, r.read_exact(&mut hdr)).await.unwrap().unwrap();
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut body = vec![0u8; len];
        r.read_exact(&mut body).await.unwrap();
        flight.extend_from_slice(&hdr);
        flight.extend_from_slice(&body);
    }
    flight
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fake_tls_end_to_end() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let mut cfg = settings(Some(&gw));
        cfg.fake_tls_domain = "example.com".into();
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        let hello = build_client_hello(&SECRET, "example.com", unix_now() as u32);
        let client_random: [u8; 32] = hello[11..43].try_into().unwrap();
        let (r, mut w) = TcpStream::connect(proxy.mtproto).await.unwrap().into_split();
        let mut r = r;
        w.write_all(&hello).await.unwrap();

        let flight = read_server_flight(&mut r).await;
        assert!(verify_server_hello(&SECRET, &client_random, &flight), "server proves it knows the secret");

        // Obfuscated2 init + data, each wrapped in TLS application records.
        let (init, mut enc, mut dec) = client_init_with_secret(&SECRET, PROTO_ABRIDGED, 2);
        let (_, all) = abridged_packets();
        let mut payload = all.clone();
        enc.apply_keystream(&mut payload);
        w.write_all(&wrap_tls_records(&[init.to_vec(), payload].concat())).await.unwrap();

        let mut tls_r = FakeTlsReader::new(r);
        let mut reply = vec![0u8; all.len()];
        let mut got = 0;
        while got < reply.len() {
            let n = tokio::time::timeout(STEP, tls_r.read(&mut reply[got..])).await.unwrap().unwrap();
            assert!(n > 0, "connection closed early");
            got += n;
        }
        dec.apply_keystream(&mut reply);
        assert_eq!(reply, xor_ff(&all));
        assert_eq!(gw.rec.lock().unwrap()[0].frames.len(), 3);
    })
    .await;
}

/// A website the proxy masquerades as.
async fn spawn_masking_site() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let l = TcpListener::bind((lo(), 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let got2 = got.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let got = got2.clone();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let n = s.read(&mut b).await.unwrap_or(0);
                got.lock().unwrap().push(b[..n].to_vec());
                let _ = s.write_all(b"HELLO FROM THE REAL SITE").await;
            });
        }
    });
    (port, got)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fake_tls_probes_see_the_real_website() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let (site_port, site_got) = spawn_masking_site().await;
        let mut cfg = settings(Some(&gw));
        cfg.fake_tls_domain = "localhost".into();
        cfg.masking_port = site_port;
        let proxy = start_proxy(cfg, tls_for(&pki)).await;
        let masked = || proxy.stats.masked.load(std::sync::atomic::Ordering::Relaxed);

        // 1. A ClientHello built with the wrong secret is relayed to the real site.
        let hello = build_client_hello(&[0x77; 16], "localhost", unix_now() as u32);
        let mut s = TcpStream::connect(proxy.mtproto).await.unwrap();
        s.write_all(&hello).await.unwrap();
        let mut reply = vec![0u8; 24];
        tokio::time::timeout(STEP, s.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(&reply, b"HELLO FROM THE REAL SITE");
        assert_eq!(site_got.lock().unwrap()[0], hello, "the site receives the prober's exact bytes");
        eventually("masked counted", || masked() == 1).await;

        // 2. A genuine hello works once…
        let good = build_client_hello(&SECRET, "localhost", unix_now() as u32);
        let mut ok = TcpStream::connect(proxy.mtproto).await.unwrap();
        ok.write_all(&good).await.unwrap();
        let mut hdr = [0u8; 5];
        tokio::time::timeout(STEP, ok.read_exact(&mut hdr)).await.unwrap().unwrap();
        assert_eq!(hdr[0], 0x16, "ServerHello");

        // 3. …and a replay of the very same bytes is treated like a probe.
        let mut replay = TcpStream::connect(proxy.mtproto).await.unwrap();
        replay.write_all(&good).await.unwrap();
        let mut r2 = vec![0u8; 24];
        tokio::time::timeout(STEP, replay.read_exact(&mut r2)).await.unwrap().unwrap();
        assert_eq!(&r2, b"HELLO FROM THE REAL SITE");
        eventually("replay masked", || masked() == 2).await;

        // 4. Non-TLS traffic gets what a plain web server would say.
        let mut plain = TcpStream::connect(proxy.mtproto).await.unwrap();
        plain.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        tokio::time::timeout(STEP, plain.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert!(resp.starts_with("HTTP/1.1 301 Moved Permanently"), "{resp}");
        assert!(resp.contains("Location: https://localhost/"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fake_tls_with_wrong_obfuscation_secret_is_silent() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let mut cfg = settings(Some(&gw));
        cfg.fake_tls_domain = "example.com".into();
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        let hello = build_client_hello(&SECRET, "example.com", unix_now() as u32);
        let (mut r, mut w) = TcpStream::connect(proxy.mtproto).await.unwrap().into_split();
        w.write_all(&hello).await.unwrap();
        read_server_flight(&mut r).await;
        let (init, _, _) = client_init_with_secret(&[0x55; 16], PROTO_ABRIDGED, 2);
        w.write_all(&wrap_tls_records(&init)).await.unwrap();
        eventually("bad handshake counted", || proxy.stats.bad.load(std::sync::atomic::Ordering::Relaxed) == 1).await;
        assert!(gw.rec.lock().unwrap().is_empty());
    })
    .await;
}

// ═════════════════════════════════ SOCKS5 ════════════════════════════════════

/// Open a SOCKS5 CONNECT through `proxy` to an IPv4 target.
async fn socks_connect(proxy: SocketAddr, ip: Ipv4Addr, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [5, 0]);
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(STEP, s.read_exact(&mut rep)).await.unwrap().unwrap();
    assert_eq!(rep[1], 0, "SOCKS5 CONNECT must succeed");
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_direct_ws_is_transparent_and_split() {
    t(async {
        let pki = gateway_pki();
        let gw = spawn_gateway(&pki, GatewayOpts::default()).await;
        let proxy = start_proxy(settings(Some(&gw)), tls_for(&pki)).await;

        // The client believes it talks to a real DC: plain obfuscated2, no secret.
        let init = generate_relay_init(PROTO_ABRIDGED, 2);
        let (mut enc, mut dec) = upstream_ciphers(&init);
        let mut s = socks_connect(proxy.socks, Ipv4Addr::new(149, 154, 167, 220), 443).await;
        s.write_all(&init).await.unwrap();
        let (packets, all) = abridged_packets();
        let mut d = all.clone();
        enc.apply_keystream(&mut d);
        s.write_all(&d).await.unwrap();

        let mut reply = vec![0u8; all.len()];
        tokio::time::timeout(STEP, s.read_exact(&mut reply)).await.unwrap().unwrap();
        dec.apply_keystream(&mut reply);
        assert_eq!(reply, xor_ff(&all));

        let rec = gw.rec.lock().unwrap().clone();
        assert_eq!(rec[0].init, Some(init), "the client's own init goes through verbatim");
        assert_eq!(rec[0].frames, packets, "and its packets are re-framed one per message");
        assert_eq!(rec[0].sni.as_deref(), Some("kws2.web.telegram.org"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_through_an_upstream_proxy_reaches_dcs_and_the_open_web() {
    t(async {
        // Everything the proxy opens is steered by the mock upstream to local backends.
        let (dc_addr, dc_rec) = spawn_dc().await;
        let (up_addr, seen) = spawn_socks_upstream(dc_addr).await;
        let pki = gateway_pki();
        let mut cfg = settings(None); // no direct route at all
        cfg.upstream_socks5 = Some(Arc::new(format!("{up_addr}").parse().unwrap()));
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        // A Telegram DC: no direct/Worker/CF route → raw TCP, via the upstream.
        let init = generate_relay_init(PROTO_ABRIDGED, 2);
        let (mut enc, mut dec) = upstream_ciphers(&init);
        let mut s = socks_connect(proxy.socks, Ipv4Addr::new(149, 154, 167, 51), 443).await;
        s.write_all(&init).await.unwrap();
        let mut msg = b"through the tunnel".to_vec();
        enc.apply_keystream(&mut msg);
        s.write_all(&msg).await.unwrap();
        let mut reply = vec![0u8; 18];
        tokio::time::timeout(STEP, s.read_exact(&mut reply)).await.unwrap().unwrap();
        dec.apply_keystream(&mut reply);
        assert_eq!(reply, xor_ff(b"through the tunnel"));
        assert_eq!(seen.lock().unwrap()[0], ("149.154.167.51".to_string(), 443));
        assert_eq!(dc_rec.lock().unwrap()[0].init, Some(init));
        assert_eq!(proxy.stats.tcp_fallback.load(std::sync::atomic::Ordering::Relaxed), 1);
    })
    .await;

    // Non-Telegram traffic is passed through the upstream too, and the *name* is
    // handed to the upstream unresolved.
    t(async {
        let echo = spawn_echo().await;
        let (up_addr, seen) = spawn_socks_upstream(echo).await;
        let pki = gateway_pki();
        let mut cfg = settings(None);
        cfg.upstream_socks5 = Some(Arc::new(format!("{up_addr}").parse().unwrap()));
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        let mut s = TcpStream::connect(proxy.socks).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        let name = b"example.org";
        let mut req = vec![5, 1, 0, 3, name.len() as u8];
        req.extend_from_slice(name);
        req.extend_from_slice(&80u16.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        tokio::time::timeout(STEP, s.read_exact(&mut rep)).await.unwrap().unwrap();
        assert_eq!(rep[1], 0);
        s.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tokio::time::timeout(STEP, s.read_exact(&mut back)).await.unwrap().unwrap();
        assert_eq!(&back, b"ping");
        assert_eq!(seen.lock().unwrap()[0], ("example.org".to_string(), 80));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_rejects_what_it_cannot_serve() {
    t(async {
        let pki = gateway_pki();
        let proxy = start_proxy(settings(None), tls_for(&pki)).await;

        // Offers only username/password: no acceptable method.
        let mut s = TcpStream::connect(proxy.socks).await.unwrap();
        s.write_all(&[5, 1, 2]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [5, 0xFF]);

        // BIND is not supported.
        let mut s = TcpStream::connect(proxy.socks).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        s.read_exact(&mut sel).await.unwrap();
        s.write_all(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80]).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 7);

        // IPv6 destinations are refused with "address type not supported".
        let mut s = TcpStream::connect(proxy.socks).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        s.read_exact(&mut sel).await.unwrap();
        let mut req = vec![5, 1, 0, 4];
        req.extend_from_slice(&[0u8; 15]);
        req.push(1);
        req.extend_from_slice(&443u16.to_be_bytes());
        s.write_all(&req).await.unwrap();
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 8);
    })
    .await;
}

// ═══════════════════════════ Live (real Telegram) ════════════════════════════

/// req_pq_multi through `addr` (an MTProto proxy) to datacenter `dc`; checks the resPQ.
async fn live_req_pq(addr: SocketAddr, dc: i16) {
    let (init, mut enc, mut dec) = client_init_with_secret(&SECRET, PROTO_ABRIDGED, dc);
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&init).await.unwrap();

    // req_pq_multi, unencrypted, abridged transport.
    let nonce = [0x5Au8; 16];
    let mut body = vec![0u8; 8];
    body.extend_from_slice(&((unix_now() << 32) & !3).to_le_bytes());
    body.extend_from_slice(&20u32.to_le_bytes());
    body.extend_from_slice(&0xbe7e8ef1u32.to_le_bytes());
    body.extend_from_slice(&nonce);
    let mut pkt = vec![(body.len() / 4) as u8];
    pkt.extend_from_slice(&body);
    enc.apply_keystream(&mut pkt);
    s.write_all(&pkt).await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(15), s.read(&mut buf)).await.unwrap().unwrap();
    assert!(n > 40, "DC{dc}: got {n} bytes");
    let mut resp = buf[..n].to_vec();
    dec.apply_keystream(&mut resp);
    let hdr = if resp[0] == 0x7F { 4 } else { 1 };
    assert_eq!(&resp[hdr + 20..hdr + 24], &[0x63, 0x24, 0x16, 0x05], "DC{dc}: resPQ");
    assert_eq!(&resp[hdr + 24..hdr + 40], &nonce, "DC{dc}: our nonce is echoed");
}

async fn live_proxy(cfg: Settings) -> (SocketAddr, Arc<Stats>) {
    let stats = Arc::new(Stats::new());
    let router = Router::new(Arc::new(cfg), stats.clone()).unwrap();
    let ml = TcpListener::bind((lo(), 0)).await.unwrap();
    let addr = ml.local_addr().unwrap();
    tokio::spawn(mtproxy::run(router, ml));
    (addr, stats)
}

/// `cargo test --test e2e -- --ignored live` — talks to the real Telegram from
/// the machine running the tests. Skipped by default (needs the Internet and a
/// network that can reach Telegram).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn live_mtproto_through_the_proxy_to_real_telegram() {
    t(async {
        let mut cfg = Settings::default();
        cfg.secret = SECRET;
        cfg.pool_size = 0;
        cfg.fallback_cfproxy = false;
        let (addr, stats) = live_proxy(cfg).await;
        for dc in [2i16, 4] {
            live_req_pq(addr, dc).await;
        }
        assert!(stats.ws.load(std::sync::atomic::Ordering::Relaxed) >= 2);
    })
    .await;
}

/// Same, but forced through a Cloudflare Worker given in `TG_PROXY_TEST_WORKER`
/// (`host[:port]`; a bare `127.0.0.1:8787` is used over plain HTTP — e.g. a local
/// `wrangler dev`). DC1 has no direct route at all, so only the Worker can serve it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn live_mtproto_through_a_worker_to_real_telegram() {
    let Ok(worker) = std::env::var("TG_PROXY_TEST_WORKER") else {
        eprintln!("TG_PROXY_TEST_WORKER is not set; skipping");
        return;
    };
    t(async {
        let mut cfg = Settings::default();
        cfg.secret = SECRET;
        cfg.pool_size = 0;
        cfg.fallback_cfproxy = false;
        cfg.dc_redirects = Default::default(); // no direct route: Worker or nothing
        cfg.cfproxy_worker_domains = vec![worker.clone()];
        cfg.disable_secure = worker.starts_with("127.0.0.1") || worker.starts_with("localhost");
        let (addr, stats) = live_proxy(cfg).await;
        for dc in [1i16, 2, 5] {
            live_req_pq(addr, dc).await;
        }
        assert_eq!(stats.cf_worker.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert_eq!(stats.tcp_fallback.load(std::sync::atomic::Ordering::Relaxed), 0, "no raw TCP was used");
    })
    .await;
}

// ═════════════════════ Failure memory and hardening ══════════════════════════

/// A "Worker" that always answers 500 and counts how often it is asked.
async fn spawn_failing_worker() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let l = TcpListener::bind((lo(), 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let n = attempts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::spawn(async move {
                let _ = read_http_head(&mut s).await;
                let _ = s.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n").await;
            });
        }
    });
    (addr, attempts)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_worker_is_not_retried_on_every_connection() {
    t(async {
        let (dc_addr, _) = spawn_dc().await;
        let (up_addr, _) = spawn_socks_upstream(dc_addr).await;
        let (worker_addr, attempts) = spawn_failing_worker().await;
        let pki = gateway_pki();
        let mut cfg = settings(None); // no direct route
        cfg.cfproxy_worker_domains = vec![worker_addr.to_string()];
        cfg.disable_secure = true;
        cfg.upstream_socks5 = Some(Arc::new(up_addr.to_string().parse().unwrap()));
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        // Every connection still succeeds: raw TCP (through the upstream) is the last resort.
        let one_connection = |tag: &'static [u8]| {
            let socks = proxy.socks;
            async move {
                let init = generate_relay_init(PROTO_ABRIDGED, 2);
                let (mut enc, mut dec) = upstream_ciphers(&init);
                let mut s = socks_connect(socks, Ipv4Addr::new(149, 154, 167, 51), 443).await;
                s.write_all(&init).await.unwrap();
                let mut m = tag.to_vec();
                enc.apply_keystream(&mut m);
                s.write_all(&m).await.unwrap();
                let mut reply = vec![0u8; tag.len()];
                tokio::time::timeout(STEP, s.read_exact(&mut reply)).await.unwrap().unwrap();
                dec.apply_keystream(&mut reply);
                assert_eq!(reply, xor_ff(tag));
            }
        };
        one_connection(b"first").await;
        // the foreground attempt and the pool's background refill each ask once
        eventually("worker was tried", || attempts.load(std::sync::atomic::Ordering::Relaxed) >= 1).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let after_first = attempts.load(std::sync::atomic::Ordering::Relaxed);

        one_connection(b"second").await;
        one_connection(b"third").await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::Relaxed),
            after_first,
            "a Worker that just failed must be left alone for a while"
        );
        assert_eq!(proxy.stats.tcp_fallback.load(std::sync::atomic::Ordering::Relaxed), 3);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fake_tls_masking_goes_through_the_upstream_proxy() {
    t(async {
        let (site_port, site_got) = spawn_masking_site().await;
        let site_addr: SocketAddr = (lo(), site_port).into();
        let (up_addr, seen) = spawn_socks_upstream(site_addr).await;
        let pki = gateway_pki();
        let mut cfg = settings(None);
        cfg.fake_tls_domain = "masking.example".into();
        cfg.masking_port = site_port;
        cfg.upstream_socks5 = Some(Arc::new(up_addr.to_string().parse().unwrap()));
        let proxy = start_proxy(cfg, tls_for(&pki)).await;

        // A probe with the wrong secret is relayed to the site — via the upstream,
        // with the site's *name* handed over unresolved.
        let hello = build_client_hello(&[0x66; 16], "masking.example", unix_now() as u32);
        let mut s = TcpStream::connect(proxy.mtproto).await.unwrap();
        s.write_all(&hello).await.unwrap();
        let mut reply = vec![0u8; 24];
        tokio::time::timeout(STEP, s.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(&reply, b"HELLO FROM THE REAL SITE");
        assert_eq!(site_got.lock().unwrap()[0], hello);
        assert_eq!(seen.lock().unwrap()[0], ("masking.example".to_string(), site_port));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_passthrough_cannot_reach_the_proxy_host_or_its_lan() {
    t(async {
        let echo = spawn_echo().await; // listens on 127.0.0.1: a "service only reachable locally"
        let pki = gateway_pki();
        let proxy = start_proxy(settings(None), tls_for(&pki)).await;

        for ip in [lo(), Ipv4Addr::new(192, 168, 1, 10), Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(169, 254, 169, 254)]
        {
            let mut s = TcpStream::connect(proxy.socks).await.unwrap();
            s.write_all(&[5, 1, 0]).await.unwrap();
            let mut sel = [0u8; 2];
            s.read_exact(&mut sel).await.unwrap();
            let mut req = vec![5, 1, 0, 1];
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(&echo.port().to_be_bytes());
            s.write_all(&req).await.unwrap();
            let mut rep = [0u8; 10];
            tokio::time::timeout(STEP, s.read_exact(&mut rep)).await.unwrap().unwrap();
            assert_eq!(rep[1], 2, "{ip}: connection not allowed by ruleset");
        }
        assert_eq!(proxy.stats.passthrough.load(std::sync::atomic::Ordering::Relaxed), 0);
    })
    .await;
}
