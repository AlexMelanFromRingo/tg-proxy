//! Pre-warmed WebSocket connections.
//!
//! Opening a TLS WebSocket costs several round trips; Telegram clients open many
//! short-lived connections, so we keep a few ready per datacenter. Pooled
//! connections are health-checked before use and rotated while idle.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::config::Settings;
use crate::ip_map::{ws_domains, DC_DEFAULT_IPS};
use crate::stats::Stats;
use crate::websocket::{connect, ConnectOpts, Target, TlsConfigs, WsConn, WsError};

/// `(dc, is_media)`
pub type PoolKey = (u16, bool);

pub const WS_PATH: &str = "/apiws";
pub const WS_PATH_TEST: &str = "/apiws_test";

const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);
const REFILL_BACKOFF_MAX: Duration = Duration::from_secs(3600);
const POOL_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

fn tag(key: PoolKey) -> String {
    format!("DC{}{}", key.0, if key.1 { "m" } else { "" })
}

fn backoff(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(12);
    Duration::from_secs(1u64 << exp).min(REFILL_BACKOFF_MAX)
}

/// Split `host[:port]`; returns `(host, port, Host header value)`.
/// Cloudflare endpoints are plain domains, but a custom port is accepted
/// (`127.0.0.1:8080` in tests, a non-standard Worker route in the wild).
pub fn endpoint(domain: &str, secure: bool) -> (String, u16, String) {
    let default = if secure { 443 } else { 80 };
    if let Some((h, p)) = domain.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            let header = if port == default { h.to_string() } else { domain.to_string() };
            return (h.to_string(), port, header);
        }
    }
    (domain.to_string(), default, domain.to_string())
}

/// Connect to a named (DNS-resolved) WebSocket endpoint such as a Cloudflare
/// Worker or a `kws{N}.<cf-domain>` host.
pub async fn connect_named(
    cfg: &Settings,
    tls: &TlsConfigs,
    domain: &str,
    path: &str,
    timeout: Duration,
) -> Result<WsConn, WsError> {
    let secure = !cfg.disable_secure;
    let (host, port, header) = endpoint(domain, secure);
    let mut o = ConnectOpts::new(Target::Host(host.clone(), port), header, path, timeout);
    o.sni = Some(host);
    o.secure = secure;
    o.buf_size = cfg.buffer_size;
    o.upstream = cfg.upstream_socks5.clone();
    connect(tls, &o).await
}

// ── Direct connector (normal SNI, with adaptive fronting) ─────────────────────

/// Connects to Telegram's WS gateway. If the plain connection is cut or times
/// out, retries with an innocuous SNI ("fronting") and remembers which mode
/// works so later connections go straight to it.
pub struct DirectConnector {
    cfg: Arc<Settings>,
    tls: Arc<TlsConfigs>,
    stats: Arc<Stats>,
    prefer_fronting: AtomicBool,
}

impl DirectConnector {
    pub fn new(cfg: Arc<Settings>, tls: Arc<TlsConfigs>, stats: Arc<Stats>) -> Arc<Self> {
        Arc::new(Self { cfg, tls, stats, prefer_fronting: AtomicBool::new(false) })
    }

    pub fn prefers_fronting(&self) -> bool {
        self.prefer_fronting.load(Relaxed)
    }

    async fn attempt(
        &self,
        ip: Ipv4Addr,
        domain: &str,
        path: &str,
        fronted: bool,
        timeout: Duration,
    ) -> Result<WsConn, WsError> {
        let addr = SocketAddr::new(ip.into(), self.cfg.gateway_port);
        let mut o = ConnectOpts::new(Target::Addr(addr), domain, path, timeout);
        o.buf_size = self.cfg.buffer_size;
        o.upstream = self.cfg.upstream_socks5.clone();
        if fronted {
            o.sni = Some(self.cfg.fronting_sni.clone());
            o.fronted = true;
        }
        connect(&self.tls, &o).await
    }

    pub async fn connect(&self, ip: Ipv4Addr, domain: &str, path: &str, timeout: Duration) -> Result<WsConn, WsError> {
        let can_front = !self.cfg.fronting_sni.is_empty();
        let prefer = can_front && self.prefer_fronting.load(Relaxed);

        if prefer {
            if let Ok(c) = self.attempt(ip, domain, path, true, timeout).await {
                self.stats.fronting.fetch_add(1, Relaxed);
                return Ok(c);
            }
        }
        match self.attempt(ip, domain, path, false, timeout).await {
            Ok(c) => {
                if can_front {
                    self.prefer_fronting.store(false, Relaxed);
                }
                Ok(c)
            }
            Err(e) if can_front && !prefer && (e.is_timeout() || e.is_reset()) => {
                match self.attempt(ip, domain, path, true, timeout).await {
                    Ok(c) => {
                        if !self.prefer_fronting.swap(true, Relaxed) {
                            info!(
                                "Plain connection to the gateway fails ({}), but SNI fronting works: preferring it",
                                e
                            );
                        }
                        self.stats.fronting.fetch_add(1, Relaxed);
                        Ok(c)
                    }
                    Err(_) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}

// ── Direct WS pool ────────────────────────────────────────────────────────────

#[derive(Default)]
struct PoolInner {
    idle: HashMap<PoolKey, VecDeque<(WsConn, Instant)>>,
    refilling: HashSet<PoolKey>,
    failures: HashMap<PoolKey, u32>,
    refill_after: HashMap<PoolKey, Instant>,
    targets: HashMap<PoolKey, Ipv4Addr>,
}

pub struct WsPool {
    inner: Mutex<PoolInner>,
    connector: Arc<DirectConnector>,
    cfg: Arc<Settings>,
    stats: Arc<Stats>,
}

impl WsPool {
    pub fn new(cfg: Arc<Settings>, stats: Arc<Stats>, connector: Arc<DirectConnector>) -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(PoolInner::default()), connector, cfg, stats })
    }

    /// A live, fresh pooled connection, if any. Always schedules a refill.
    pub async fn get(self: &Arc<Self>, key: PoolKey, target: Ipv4Addr) -> Option<WsConn> {
        if self.cfg.pool_size == 0 {
            return None;
        }
        loop {
            let entry = {
                let mut g = self.inner.lock().unwrap();
                g.targets.insert(key, target);
                g.idle.get_mut(&key).and_then(|b| b.pop_front())
            };
            let Some((mut conn, created)) = entry else { break };
            if created.elapsed() > self.cfg.pool_max_age || !conn.is_alive().await {
                debug!("Pool: discarding stale entry for {}", tag(key));
                tokio::spawn(conn.close());
                continue;
            }
            self.stats.pool_hits.fetch_add(1, Relaxed);
            self.report_success(key);
            self.schedule_refill(key, target);
            return Some(conn);
        }
        self.stats.pool_misses.fetch_add(1, Relaxed);
        self.schedule_refill(key, target);
        None
    }

    /// Number of idle connections currently held for `key`.
    pub fn idle_len(&self, key: PoolKey) -> usize {
        self.inner.lock().unwrap().idle.get(&key).map_or(0, |b| b.len())
    }

    pub fn report_success(&self, key: PoolKey) {
        let mut g = self.inner.lock().unwrap();
        g.failures.remove(&key);
        g.refill_after.remove(&key);
    }

    fn schedule_refill(self: &Arc<Self>, key: PoolKey, target: Ipv4Addr) {
        if self.cfg.pool_size == 0 {
            return;
        }
        {
            let mut g = self.inner.lock().unwrap();
            if g.refilling.contains(&key) {
                return;
            }
            if g.refill_after.get(&key).is_some_and(|t| Instant::now() < *t) {
                return;
            }
            g.refilling.insert(key);
        }
        let this = Arc::clone(self);
        tokio::spawn(async move { this.refill(key, target).await });
    }

    async fn refill(self: Arc<Self>, key: PoolKey, target: Ipv4Addr) {
        let needed = {
            let g = self.inner.lock().unwrap();
            let have = g.idle.get(&key).map_or(0, |b| b.len());
            self.cfg.pool_size.saturating_sub(have)
        };

        let mut connected = 0usize;
        if needed > 0 {
            let mut set = JoinSet::new();
            for _ in 0..needed {
                let this = Arc::clone(&self);
                set.spawn(async move { this.connect_one(key, target).await });
            }
            // Each connection becomes available the moment it is ready: one slow
            // handshake must not hold back the ones that already succeeded.
            while let Some(r) = set.join_next().await {
                if let Ok(Some(c)) = r {
                    connected += 1;
                    let mut g = self.inner.lock().unwrap();
                    g.idle.entry(key).or_default().push_back((c, Instant::now()));
                }
            }
        }

        let mut g = self.inner.lock().unwrap();
        if needed > 0 {
            if connected > 0 {
                g.failures.remove(&key);
                g.refill_after.remove(&key);
            } else {
                let f = g.failures.entry(key).or_insert(0);
                *f += 1;
                let delay = backoff(*f);
                g.refill_after.insert(key, Instant::now() + delay);
                info!("WS pool refill failed for {}, retry in {}s", tag(key), delay.as_secs());
            }
        }
        g.refilling.remove(&key);
        debug!("WS pool {}: +{} ({} wanted)", tag(key), connected, needed);
    }

    async fn connect_one(&self, key: PoolKey, ip: Ipv4Addr) -> Option<WsConn> {
        for domain in ws_domains(key.0, key.1) {
            match self.connector.connect(ip, &domain, WS_PATH, POOL_CONNECT_TIMEOUT).await {
                Ok(c) => return Some(c),
                Err(e) if e.is_redirect() => continue,
                Err(e) => {
                    debug!("Pool pre-connect {} failed: {}", tag(key), e);
                    return None;
                }
            }
        }
        None
    }

    /// Fill the pool for every configured DC and start the idle-rotation task.
    pub fn warmup(self: &Arc<Self>) {
        if self.cfg.pool_size == 0 {
            return;
        }
        for (&dc, &ip) in &self.cfg.dc_redirects {
            for media in [false, true] {
                self.inner.lock().unwrap().targets.insert((dc, media), ip);
                self.schedule_refill((dc, media), ip);
            }
        }
        info!("WS pool warmup started for {} DC(s)", self.cfg.dc_redirects.len());

        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(MAINTENANCE_INTERVAL).await;
                this.maintain().await;
            }
        });
    }

    /// Drop expired / dead idle connections and top the pool back up.
    async fn maintain(self: &Arc<Self>) {
        let keys: Vec<(PoolKey, Ipv4Addr)> = {
            let g = self.inner.lock().unwrap();
            g.targets.iter().map(|(k, v)| (*k, *v)).collect()
        };
        for (key, target) in keys {
            let bucket = {
                let mut g = self.inner.lock().unwrap();
                g.idle.get_mut(&key).map(std::mem::take)
            };
            if let Some(bucket) = bucket {
                let mut keep = VecDeque::new();
                for (mut conn, created) in bucket {
                    if created.elapsed() >= self.cfg.pool_max_age || !conn.is_alive().await {
                        tokio::spawn(conn.close());
                    } else {
                        keep.push_back((conn, created));
                    }
                }
                let mut g = self.inner.lock().unwrap();
                let b = g.idle.entry(key).or_default();
                for item in keep.into_iter().rev() {
                    b.push_front(item);
                }
            }
            let short = {
                let g = self.inner.lock().unwrap();
                g.idle.get(&key).map_or(0, |b| b.len()) < self.cfg.pool_size
            };
            if short {
                self.schedule_refill(key, target);
            }
        }
    }
}

// ── Cloudflare Worker pool ────────────────────────────────────────────────────

const CF_POOL_MAX_AGE: Duration = Duration::from_secs(100);
const CF_PER_DC_LIMIT: usize = 1;
const CF_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// After a refill finds no working Worker, wait this long before trying again.
const CF_REFILL_RETRY: Duration = Duration::from_secs(30);

/// `/apiws?dst=<ip>&dc=<n>`: the Worker opens a raw TCP socket to `dst:443`.
pub fn worker_path(dst: Ipv4Addr, dc: u16) -> String {
    format!("{WS_PATH}?dst={dst}&dc={dc}")
}

struct CfEntry {
    conn: WsConn,
    created: Instant,
    domain: String,
    dst: Ipv4Addr,
}

#[derive(Default)]
struct CfInner {
    idle: HashMap<u16, VecDeque<CfEntry>>,
    refilling: HashSet<u16>,
    refill_after: HashMap<u16, Instant>,
}

pub struct CfWorkerPool {
    inner: Mutex<CfInner>,
    cfg: Arc<Settings>,
    tls: Arc<TlsConfigs>,
    stats: Arc<Stats>,
}

impl CfWorkerPool {
    pub fn new(cfg: Arc<Settings>, tls: Arc<TlsConfigs>, stats: Arc<Stats>) -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(CfInner::default()), cfg, tls, stats })
    }

    /// Worker domains in random order (spreads load across several Workers).
    pub fn available_domains(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut v: Vec<String> =
            self.cfg.cfproxy_worker_domains.iter().filter(|d| seen.insert(d.to_ascii_lowercase())).cloned().collect();
        v.shuffle(&mut rand::thread_rng());
        v
    }

    pub async fn connect(&self, domain: &str, dst: Ipv4Addr, dc: u16, timeout: Duration) -> Result<WsConn, WsError> {
        connect_named(&self.cfg, &self.tls, domain, &worker_path(dst, dc), timeout).await
    }

    pub async fn get(self: &Arc<Self>, dc: u16, dst: Ipv4Addr) -> Option<(WsConn, String)> {
        loop {
            let entry = self.inner.lock().unwrap().idle.get_mut(&dc).and_then(|b| b.pop_front());
            let Some(mut e) = entry else { break };
            if e.dst != dst || e.created.elapsed() > CF_POOL_MAX_AGE || !e.conn.is_alive().await {
                tokio::spawn(e.conn.close());
                continue;
            }
            self.stats.cf_pool_hits.fetch_add(1, Relaxed);
            self.schedule_refill(dc, dst);
            return Some((e.conn, e.domain));
        }
        self.stats.cf_pool_misses.fetch_add(1, Relaxed);
        self.schedule_refill(dc, dst);
        None
    }

    fn schedule_refill(self: &Arc<Self>, dc: u16, dst: Ipv4Addr) {
        if self.cfg.cfproxy_worker_domains.is_empty() || self.cfg.pool_size == 0 {
            return;
        }
        {
            let mut g = self.inner.lock().unwrap();
            if g.refill_after.get(&dc).is_some_and(|t| Instant::now() < *t) || !g.refilling.insert(dc) {
                return;
            }
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let target = this.cfg.pool_size.min(CF_PER_DC_LIMIT);
            loop {
                let have = this.inner.lock().unwrap().idle.get(&dc).map_or(0, |b| b.len());
                if have >= target {
                    break;
                }
                let mut got = None;
                for domain in this.available_domains() {
                    if let Ok(conn) = this.connect(&domain, dst, dc, CF_CONNECT_TIMEOUT).await {
                        got = Some((conn, domain));
                        break;
                    }
                }
                let Some((conn, domain)) = got else {
                    this.inner.lock().unwrap().refill_after.insert(dc, Instant::now() + CF_REFILL_RETRY);
                    break;
                };
                this.inner.lock().unwrap().idle.entry(dc).or_default().push_back(CfEntry {
                    conn,
                    created: Instant::now(),
                    domain,
                    dst,
                });
            }
            this.inner.lock().unwrap().refilling.remove(&dc);
            debug!("CF worker pool DC{} refilled", dc);
        });
    }

    /// Pre-connect for the DCs that have no direct route (they need the Worker).
    pub fn warmup(self: &Arc<Self>) {
        if self.cfg.cfproxy_worker_domains.is_empty() {
            return;
        }
        let todo: Vec<_> = DC_DEFAULT_IPS.iter().filter(|(dc, _)| !self.cfg.dc_redirects.contains_key(dc)).collect();
        for (dc, ip) in &todo {
            self.schedule_refill(*dc, *ip);
        }
        info!("CF worker pool warmup started for {} DC(s)", todo.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(5), Duration::from_secs(16));
        assert_eq!(backoff(13), Duration::from_secs(3600).min(Duration::from_secs(4096)));
        assert_eq!(backoff(100), Duration::from_secs(3600));
    }

    #[test]
    fn endpoint_parsing() {
        assert_eq!(
            endpoint("w.example.workers.dev", true),
            ("w.example.workers.dev".into(), 443, "w.example.workers.dev".into())
        );
        assert_eq!(
            endpoint("w.example.workers.dev", false),
            ("w.example.workers.dev".into(), 80, "w.example.workers.dev".into())
        );
        assert_eq!(endpoint("127.0.0.1:8080", true), ("127.0.0.1".into(), 8080, "127.0.0.1:8080".into()));
        // explicit default port is dropped from the Host header
        assert_eq!(endpoint("x.example:443", true).2, "x.example");
        // not a port
        assert_eq!(endpoint("x.example:abc", true).1, 443);
    }

    #[test]
    fn worker_path_format() {
        assert_eq!(worker_path(Ipv4Addr::new(149, 154, 167, 51), 2), "/apiws?dst=149.154.167.51&dc=2");
    }
}
