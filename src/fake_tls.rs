//! "Fake TLS" (`ee` secrets) for the MTProto-proxy listener.
//!
//! The client opens what looks like a TLS 1.3 handshake to a real website
//! (`--fake-tls-domain`); the ClientHello's random field carries an HMAC keyed
//! with the proxy secret, which only a legitimate client can produce. Anything
//! that does not verify — scanners, censors' active probes — is transparently
//! relayed to the real website, so the server behaves like an ordinary web host.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;
use tracing::{debug, warn};

type HmacSha256 = Hmac<Sha256>;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_CCS: u8 = 0x14;
const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const SESSION_ID_OFFSET: usize = 44;
const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;
const MASKING_MAX_DURATION: Duration = Duration::from_secs(120);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

fn hmac(secret: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub timestamp: u32,
}

/// Verify a ClientHello against `secret`. `now` is the current Unix time.
pub fn verify_client_hello(data: &[u8], secret: &[u8; 16], now: u64) -> Option<ClientHello> {
    // 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random)
    if data.len() < 43 || data[0] != TLS_RECORD_HANDSHAKE || data[5] != 0x01 {
        return None;
    }
    let random: [u8; 32] = data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32].try_into().ok()?;
    let mut zeroed = data.to_vec();
    zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32].fill(0);
    let expected = hmac(secret, &[&zeroed]);

    // The first 28 bytes must equal the HMAC; compare without early exit.
    let mut diff = 0u8;
    for i in 0..28 {
        diff |= expected[i] ^ random[i];
    }
    if diff != 0 {
        return None;
    }
    // The last 4 bytes are the client's clock, XORed with the HMAC's tail.
    let ts = u32::from_le_bytes([
        random[28] ^ expected[28],
        random[29] ^ expected[29],
        random[30] ^ expected[30],
        random[31] ^ expected[31],
    ]);
    if (now as i64 - ts as i64).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }
    let mut session_id = [0u8; 32];
    if data.len() >= SESSION_ID_OFFSET + 32 && data[43] == 0x20 {
        session_id.copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32]);
    }
    Some(ClientHello { random, session_id, timestamp: ts })
}

/// Remembers recently seen ClientHello randoms so a captured hello cannot be
/// replayed at us (a classic active-probing trick) within the clock tolerance.
#[derive(Default)]
pub struct ReplayCache {
    seen: Mutex<HashMap<[u8; 32], Instant>>,
}

impl ReplayCache {
    /// `true` if `random` has not been seen recently (and records it).
    pub fn check_and_insert(&self, random: [u8; 32]) -> bool {
        let ttl = Duration::from_secs(2 * TIMESTAMP_TOLERANCE as u64 + 5);
        let now = Instant::now();
        let mut m = self.seen.lock().unwrap();
        if m.len() > 4096 {
            m.retain(|_, t| now.duration_since(*t) < ttl);
        }
        match m.get(&random) {
            Some(t) if now.duration_since(*t) < ttl => false,
            _ => {
                m.insert(random, now);
                true
            }
        }
    }
}

/// A plausible TLS 1.3 server flight: ServerHello, change-cipher-spec, and one
/// opaque application-data record of a believable size. The server random is an
/// HMAC over the client's random, proving to the client we know the secret.
pub fn build_server_hello(secret: &[u8; 16], client_random: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut sh = Vec::with_capacity(127);
    sh.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x7a]); // record: handshake, 122 bytes
    sh.extend_from_slice(&[0x02, 0x00, 0x00, 0x76]); // ServerHello, 118 bytes
    sh.extend_from_slice(&[0x03, 0x03]); // legacy version
    sh.extend_from_slice(&[0u8; 32]); // random (filled in below)
    sh.push(0x20);
    sh.extend_from_slice(session_id);
    sh.extend_from_slice(&[0x13, 0x01, 0x00]); // TLS_AES_128_GCM_SHA256, no compression
    sh.extend_from_slice(&[0x00, 0x2e]); // extensions: 46 bytes
    sh.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]); // key_share x25519
    let mut pubkey = [0u8; 32];
    rng.fill_bytes(&mut pubkey);
    sh.extend_from_slice(&pubkey);
    sh.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions: TLS 1.3

    let size: usize = rng.gen_range(1900..=2100);
    let mut app = vec![0x17, 0x03, 0x03];
    app.extend_from_slice(&(size as u16).to_be_bytes());
    let mut body = vec![0u8; size];
    rng.fill_bytes(&mut body);
    app.extend_from_slice(&body);

    let mut resp = sh;
    resp.extend_from_slice(&CCS_FRAME);
    resp.extend_from_slice(&app);

    let server_random = hmac(secret, &[client_random, &resp]);
    resp[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32].copy_from_slice(&server_random);
    resp
}

/// Wrap `data` in TLS application-data records.
pub fn wrap_tls_records(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / TLS_APPDATA_MAX + 1));
    for chunk in data.chunks(TLS_APPDATA_MAX) {
        out.extend_from_slice(&[0x17, 0x03, 0x03]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// Reads the payload of TLS application-data records as a plain byte stream.
pub struct FakeTlsReader {
    inner: OwnedReadHalf,
    record_left: usize,
}

impl FakeTlsReader {
    pub fn new(inner: OwnedReadHalf) -> Self {
        Self { inner, record_left: 0 }
    }

    /// Up to `buf.len()` payload bytes; `0` on EOF or a non-application record.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.record_left == 0 {
            let mut hdr = [0u8; 5];
            match self.inner.read_exact(&mut hdr).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            match hdr[0] {
                TLS_RECORD_CCS => {
                    let mut skip = vec![0u8; len];
                    self.inner.read_exact(&mut skip).await?;
                }
                TLS_RECORD_APPDATA => self.record_left = len,
                _ => return Ok(0),
            }
        }
        let n = buf.len().min(self.record_left);
        let r = self.inner.read(&mut buf[..n]).await?;
        self.record_left -= r;
        Ok(r)
    }
}

pub struct FakeTlsWriter {
    inner: OwnedWriteHalf,
}

impl FakeTlsWriter {
    pub fn new(inner: OwnedWriteHalf) -> Self {
        Self { inner }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_all(&wrap_tls_records(data)).await
    }

    pub async fn shutdown(&mut self) {
        let _ = self.inner.shutdown().await;
    }
}

/// Relay a connection that failed fake-TLS verification to the real website.
/// `stats.masked` is bumped as soon as the relay is established, not when it ends.
pub async fn proxy_to_masking_domain(
    mut client_r: OwnedReadHalf,
    mut client_w: OwnedWriteHalf,
    initial: &[u8],
    cfg: &crate::config::Settings,
    label: &str,
    stats: &crate::stats::Stats,
) {
    let (domain, port) = (cfg.fake_tls_domain.as_str(), cfg.masking_port);
    let via = cfg.upstream_socks5.as_deref();

    let target = crate::websocket::Target::Host(domain.to_string(), port);
    let upstream = match timeout(Duration::from_secs(10), crate::upstream::connect(&target, via)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("[{}] masking: cannot connect to {}:{}: {}", label, domain, port, e);
            return;
        }
        Err(_) => {
            warn!("[{}] masking: connecting to {}:{} timed out", label, domain, port);
            return;
        }
    };
    stats.masked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    debug!("[{}] masking -> {}:{}", label, domain, port);
    let (mut up_r, mut up_w) = upstream.into_split();

    let relay = async {
        if !initial.is_empty() && up_w.write_all(initial).await.is_err() {
            return;
        }
        let to_site = async {
            let _ = tokio::io::copy(&mut client_r, &mut up_w).await;
            let _ = up_w.shutdown().await;
        };
        let to_client = async {
            let _ = tokio::io::copy(&mut up_r, &mut client_w).await;
            let _ = client_w.shutdown().await;
        };
        tokio::join!(to_site, to_client);
    };
    let _ = timeout(MASKING_MAX_DURATION, relay).await;
}

// ── Client simulation (tests and diagnostics) ─────────────────────────────────

/// Build a ClientHello like an `ee`-secret Telegram client would send:
/// valid structure, with the HMAC/timestamp placed in the random field.
pub fn build_client_hello(secret: &[u8; 16], sni: &str, timestamp: u32) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut session_id);

    let name = sni.as_bytes();
    let mut ext = Vec::new();
    // server_name
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
    ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    ext.push(0x00);
    ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    ext.extend_from_slice(name);
    // supported_versions
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]); // random, filled in below
    body.push(0x20);
    body.extend_from_slice(&session_id);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
    body.extend_from_slice(&[0x01, 0x00]); // compression
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);

    let digest = hmac(secret, &[&rec]);
    let ts = timestamp.to_le_bytes();
    let mut random = digest;
    for i in 0..4 {
        random[28 + i] = digest[28 + i] ^ ts[i];
    }
    rec[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32].copy_from_slice(&random);
    rec
}

/// Client-side check of the server flight: the server random must be the HMAC
/// over (client random || flight with a zeroed random).
pub fn verify_server_hello(secret: &[u8; 16], client_random: &[u8; 32], flight: &[u8]) -> bool {
    if flight.len() < CLIENT_RANDOM_OFFSET + 32 {
        return false;
    }
    let mut zeroed = flight.to_vec();
    zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32].fill(0);
    hmac(secret, &[client_random, &zeroed])[..] == flight[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    const SECRET: [u8; 16] = [0x42; 16];

    #[test]
    fn client_hello_verifies() {
        let now = 1_800_000_000u64;
        let hello = build_client_hello(&SECRET, "example.com", now as u32);
        let v = verify_client_hello(&hello, &SECRET, now).expect("valid hello");
        assert_eq!(v.timestamp, now as u32);
        assert_eq!(&v.random[..], &hello[11..43]);
        assert_eq!(&v.session_id[..], &hello[44..76]);
    }

    #[test]
    fn client_hello_rejections() {
        let now = 1_800_000_000u64;
        let hello = build_client_hello(&SECRET, "example.com", now as u32);
        assert!(verify_client_hello(&hello, &[0x43; 16], now).is_none(), "wrong secret");
        assert!(verify_client_hello(&hello, &SECRET, now + 121).is_none(), "too old");
        assert!(verify_client_hello(&hello, &SECRET, now - 121).is_none(), "from the future");
        assert!(verify_client_hello(&hello, &SECRET, now + 119).is_some(), "within tolerance");

        let mut tampered = hello.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_client_hello(&tampered, &SECRET, now).is_none(), "any change breaks the HMAC");

        assert!(verify_client_hello(&hello[..40], &SECRET, now).is_none(), "truncated");
        let mut not_hs = hello.clone();
        not_hs[0] = 0x17;
        assert!(verify_client_hello(&not_hs, &SECRET, now).is_none());
        // plain HTTP and random bytes are never accepted
        assert!(verify_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n.............", &SECRET, now).is_none());
    }

    #[test]
    fn replay_cache_blocks_second_use() {
        let c = ReplayCache::default();
        assert!(c.check_and_insert([1; 32]));
        assert!(!c.check_and_insert([1; 32]));
        assert!(c.check_and_insert([2; 32]));
    }

    #[test]
    fn server_hello_structure_and_proof() {
        let now = 1_800_000_000u64;
        let hello = build_client_hello(&SECRET, "example.com", now as u32);
        let v = verify_client_hello(&hello, &SECRET, now).unwrap();
        let flight = build_server_hello(&SECRET, &v.random, &v.session_id);

        // record 1: handshake, length matches
        assert_eq!(&flight[..3], &[0x16, 0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([flight[3], flight[4]]) as usize, 122);
        assert_eq!(&flight[44..76], &v.session_id[..], "echoes the session id");
        // record 2: CCS, record 3: application data with the announced length
        assert_eq!(&flight[127..133], &CCS_FRAME);
        assert_eq!(&flight[133..136], &[0x17, 0x03, 0x03]);
        let app_len = u16::from_be_bytes([flight[136], flight[137]]) as usize;
        assert!((1900..=2100).contains(&app_len));
        assert_eq!(flight.len(), 138 + app_len);

        assert!(verify_server_hello(&SECRET, &v.random, &flight));
        assert!(!verify_server_hello(&[0; 16], &v.random, &flight), "wrong secret fails the proof");
        let mut other = v.random;
        other[0] ^= 1;
        assert!(!verify_server_hello(&SECRET, &other, &flight), "bound to this client random");
    }

    #[test]
    fn records_are_chunked_at_16k() {
        let data = vec![7u8; TLS_APPDATA_MAX * 2 + 10];
        let w = wrap_tls_records(&data);
        assert_eq!(w.len(), data.len() + 15);
        assert_eq!(&w[..3], &[0x17, 0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([w[3], w[4]]) as usize, TLS_APPDATA_MAX);
        assert!(wrap_tls_records(&[]).is_empty());
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap());
        let (a, b) = tokio::join!(c, l.accept());
        (a.unwrap(), b.unwrap().0)
    }

    #[tokio::test]
    async fn stream_roundtrip_skips_ccs_and_spans_records() {
        let (a, b) = tcp_pair().await;
        let (_ar, aw) = a.into_split();
        let (br, _bw) = b.into_split();
        let mut writer = FakeTlsWriter::new(aw);
        let mut reader = FakeTlsReader::new(br);

        // Raw bytes: a CCS record, then two app records split mid-way by the reader.
        let msg: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        writer.inner.write_all(&CCS_FRAME).await.unwrap();
        writer.write_all(&msg).await.unwrap();
        writer.shutdown().await;

        let mut got = Vec::new();
        let mut buf = [0u8; 1000];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn reader_stops_on_unexpected_record_type() {
        let (a, b) = tcp_pair().await;
        let (_ar, mut aw) = a.into_split();
        let (br, _bw) = b.into_split();
        aw.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).await.unwrap(); // alert
        let mut reader = FakeTlsReader::new(br);
        let mut buf = [0u8; 8];
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
    }
}
