//! Pool of Cloudflare-proxied domains ("CfProxy") and its remote refresh.
//!
//! A CF-proxied domain has `kws{N}` A-records pointing at Telegram's DCs, so
//! `wss://kws{N}.<domain>/apiws` reaches Telegram through Cloudflare's edge —
//! an address range censors are reluctant to block outright.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::seq::SliceRandom;
use rand::Rng;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::config::{
    decode_cf_domain, default_cfproxy_domains, normalize_domain_pool, CFPROXY_DOMAINS_URL_HOST,
    CFPROXY_DOMAINS_URL_PATH, CFPROXY_MIN_VALID_DOMAINS, GITHUB_PINNED_IP,
};
use crate::upstream::UpstreamSocks;
use crate::websocket::{Target, TlsConfigs};

const DCS: [u16; 6] = [1, 2, 3, 4, 5, 203];
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct State {
    domains: Vec<String>,
    dc_to_domain: HashMap<u16, String>,
}

#[derive(Default)]
pub struct Balancer {
    state: Mutex<State>,
}

impl Balancer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.state.lock().unwrap().domains.is_empty()
    }

    pub fn domains(&self) -> Vec<String> {
        self.state.lock().unwrap().domains.clone()
    }

    /// Replace the pool. A list with the same members is a no-op, so a periodic
    /// refresh does not reshuffle domains that are already working.
    pub fn update_domains_list(&self, list: Vec<String>) {
        let mut s = self.state.lock().unwrap();
        let mut a = s.domains.clone();
        let mut b = list.clone();
        a.sort();
        b.sort();
        if a == b {
            return;
        }
        let mut rng = rand::thread_rng();
        s.dc_to_domain = if list.is_empty() {
            HashMap::new()
        } else {
            DCS.iter().map(|&dc| (dc, list[rng.gen_range(0..list.len())].clone())).collect()
        };
        s.domains = list;
    }

    /// Remember the domain that worked for `dc`. Returns whether it changed.
    pub fn update_domain_for_dc(&self, dc: u16, domain: &str) -> bool {
        let mut s = self.state.lock().unwrap();
        if s.dc_to_domain.get(&dc).map(String::as_str) == Some(domain) {
            return false;
        }
        s.dc_to_domain.insert(dc, domain.to_string());
        true
    }

    /// Candidate base domains for `dc`: the last good one first, then the rest
    /// in random order.
    pub fn domains_for_dc(&self, dc: u16) -> Vec<String> {
        let s = self.state.lock().unwrap();
        let current = s.dc_to_domain.get(&dc).cloned();
        let mut rest: Vec<String> = s.domains.iter().filter(|d| Some(*d) != current.as_ref()).cloned().collect();
        rest.shuffle(&mut rand::thread_rng());
        current.into_iter().chain(rest).collect()
    }

    /// Install the built-in pool, or the user's own domains (which are never
    /// refreshed from the network).
    pub fn init(&self, user_domains: &[String]) {
        if user_domains.is_empty() {
            self.update_domains_list(default_cfproxy_domains());
        } else {
            self.update_domains_list(user_domains.to_vec());
        }
    }

    /// Fetch the community list once and adopt it if it looks sane.
    pub async fn refresh_once(&self, tls: &TlsConfigs, upstream: Option<&UpstreamSocks>) -> bool {
        let path = format!("{}?{}", CFPROXY_DOMAINS_URL_PATH, random_token(7));
        let body = match https_get(
            &tls.normal,
            CFPROXY_DOMAINS_URL_HOST,
            &path,
            Some(GITHUB_PINNED_IP),
            Duration::from_secs(10),
            upstream,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                warn!("CF proxy domain refresh failed ({}); keeping the current pool", e);
                return false;
            }
        };
        let fetched = parse_domain_list(&String::from_utf8_lossy(&body));
        let pool = normalize_domain_pool(&fetched);
        if pool.len() >= CFPROXY_MIN_VALID_DOMAINS {
            self.update_domains_list(pool.clone());
            info!("CF proxy domain pool updated ({} domains)", pool.len());
            true
        } else {
            warn!(
                "Ignoring fetched CF proxy domains: {} valid of {} (need at least {})",
                pool.len(),
                fetched.len(),
                CFPROXY_MIN_VALID_DOMAINS
            );
            false
        }
    }

    pub fn spawn_refresh(self: &Arc<Self>, tls: Arc<TlsConfigs>, upstream: Option<Arc<UpstreamSocks>>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                this.refresh_once(&tls, upstream.as_deref()).await;
                tokio::time::sleep(REFRESH_INTERVAL).await;
            }
        });
    }
}

fn random_token(n: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect()
}

/// One domain per line, `#` comments, entries in the encoded form.
pub fn parse_domain_list(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(decode_cf_domain).collect()
}

// ── Tiny HTTPS GET ────────────────────────────────────────────────────────────

/// GET `https://host/path`. Tries the pinned IP first (if any), then DNS.
pub async fn https_get(
    tls: &Arc<rustls::ClientConfig>,
    host: &str,
    path: &str,
    pinned: Option<Ipv4Addr>,
    t: Duration,
    upstream: Option<&UpstreamSocks>,
) -> io::Result<Vec<u8>> {
    let mut targets = Vec::new();
    if let Some(ip) = pinned {
        targets.push(Target::Addr((ip, 443).into()));
    }
    targets.push(Target::Host(host.to_string(), 443));

    let mut last = io::Error::other("no target");
    for target in targets {
        match timeout(t, get_once(tls, &target, host, path, upstream)).await {
            Ok(Ok(body)) => return Ok(body),
            Ok(Err(e)) => last = e,
            Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, "timed out"),
        }
    }
    Err(last)
}

async fn get_once(
    tls: &Arc<rustls::ClientConfig>,
    target: &Target,
    host: &str,
    path: &str,
    upstream: Option<&UpstreamSocks>,
) -> io::Result<Vec<u8>> {
    let tcp = crate::upstream::connect(target, upstream).await?;
    let name = ServerName::try_from(host.to_owned()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut s = TlsConnector::from(tls.clone()).connect(name, tcp).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tg-proxy\r\nAccept: */*\r\n\
         Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > 1 << 20 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "response too large"));
                }
            }
            // Peers often close without TLS close_notify; the data we have is what counts.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    parse_http_response(&raw)
}

pub fn parse_http_response(raw: &[u8]) -> io::Result<Vec<u8>> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| bad("incomplete HTTP response"))?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad("bad status line"))?;
    if status != 200 {
        return Err(bad(&format!("HTTP {status}")));
    }
    let header = |name: &str| {
        lines.clone().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_ascii_lowercase())
        })
    };
    let body = &raw[end + 4..];
    if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        return decode_chunked(body).ok_or_else(|| bad("bad chunked encoding"));
    }
    if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if body.len() < len {
            return Err(bad("truncated body"));
        }
        return Ok(body[..len].to_vec());
    }
    Ok(body.to_vec())
}

pub fn decode_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = data.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&data[..eol]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        data = &data[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        let end = size.checked_add(2)?;
        if size > 1 << 20 || data.len() < end {
            return None;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_list_does_not_reshuffle() {
        let b = Balancer::new();
        let list: Vec<String> = ["a.example", "b.example", "c.example", "d.example"].map(String::from).to_vec();
        b.update_domains_list(list.clone());
        let before: Vec<_> = DCS.iter().map(|&d| b.domains_for_dc(d)[0].clone()).collect();
        let mut reordered = list.clone();
        reordered.reverse();
        b.update_domains_list(reordered); // same members → no-op
        let after: Vec<_> = DCS.iter().map(|&d| b.domains_for_dc(d)[0].clone()).collect();
        assert_eq!(before, after);
    }

    #[test]
    fn current_domain_goes_first_and_every_domain_is_offered_once() {
        let b = Balancer::new();
        let list: Vec<String> = ["a.example", "b.example", "c.example"].map(String::from).to_vec();
        b.update_domains_list(list.clone());
        // Pick a domain that is not already the (randomly assigned) current one.
        let current = b.domains_for_dc(2)[0].clone();
        let other = list.iter().find(|d| **d != current).unwrap().clone();
        assert!(b.update_domain_for_dc(2, &other));
        assert!(!b.update_domain_for_dc(2, &other));
        for _ in 0..20 {
            let d = b.domains_for_dc(2);
            assert_eq!(d[0], other);
            let mut sorted = d.clone();
            sorted.sort();
            assert_eq!(sorted, list);
        }
        // unknown DC (e.g. a test DC): no preferred domain, still all offered
        assert_eq!(b.domains_for_dc(999).len(), 3);
    }

    #[test]
    fn init_prefers_user_domains() {
        let b = Balancer::new();
        b.init(&["mine.example".into()]);
        assert_eq!(b.domains(), vec!["mine.example"]);
        let b = Balancer::new();
        b.init(&[]);
        assert_eq!(b.domains().len(), 20);
    }

    #[test]
    fn domain_list_parsing_decodes_and_skips_comments() {
        let text = "# comment\n\nvirkgj.com\n  vmmzovy.com  \nplain.example\n";
        assert_eq!(parse_domain_list(text), vec!["pclead.co.uk", "offshor.co.uk", "plain.example"]);
    }

    #[test]
    fn http_parsing() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(parse_http_response(plain).unwrap(), b"hello");
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(chunked).unwrap(), b"hello world");
        assert!(parse_http_response(b"HTTP/1.1 404 Not Found\r\n\r\n").is_err());
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort").is_err());
        assert!(parse_http_response(b"garbage").is_err());
    }

    #[test]
    fn chunk_decoder_rejects_garbage() {
        assert!(decode_chunked(b"zz\r\nabc\r\n0\r\n\r\n").is_none());
        assert!(decode_chunked(b"10\r\nshort\r\n").is_none());
        assert_eq!(decode_chunked(b"0\r\n\r\n").unwrap(), Vec::<u8>::new());
    }
}
