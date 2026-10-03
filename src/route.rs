//! Route selection: how does a given Telegram connection reach its datacenter?
//!
//! Preference order, mirroring what works best on censored networks:
//!
//! 1. **Direct WebSocket** to Telegram's own gateway (plain SNI, or fronted).
//! 2. **Cloudflare Worker** — a free user-owned relay that opens a raw TCP socket
//!    to the DC from Cloudflare's network.
//! 3. **Cloudflare-proxied domains** — `wss://kws{N}.<domain>/apiws`.
//! 4. **Raw TCP** straight to the DC (works wherever the DC is not blocked).
//!
//! Failures are remembered so a blocked path costs one slow attempt, not one per
//! connection.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::balancer::Balancer;
use crate::config::Settings;
use crate::ip_map::{dc_default_ip, ws_domains};
use crate::pool::{connect_named, CfWorkerPool, DirectConnector, WsPool, WS_PATH, WS_PATH_TEST};
use crate::stats::Stats;
use crate::websocket::{build_tls_configs, tune_socket, Target, TlsConfigs, WsConn};

/// After a *timeout* to a gateway IP, skip direct attempts for this long (if a
/// Cloudflare route can take over). A timeout is the signature of an IP block.
pub const IP_FAIL_COOLDOWN: Duration = Duration::from_secs(3600);
/// After any other direct failure for a DC, use the fallback chain for this long.
pub const DC_FAIL_COOLDOWN: Duration = Duration::from_secs(60);
/// Probe timeout while a DC is in cooldown (don't stall the user on a retest).
pub const WS_FAIL_TIMEOUT: Duration = Duration::from_secs(2);
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(10);
/// A Worker / Cloudflare domain that just failed is skipped for this long, so a dead
/// leg costs one slow attempt per window instead of one per client connection.
pub const LEG_FAIL_COOLDOWN: Duration = Duration::from_secs(30);
const CF_WAVE: usize = 3;
const CF_WAVES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DcKey {
    pub dc: u16,
    pub media: bool,
    pub test: bool,
}

impl fmt::Display for DcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DC{}{}{}", self.dc, if self.test { "t" } else { "" }, if self.media { "m" } else { "" })
    }
}

pub struct Request<'a> {
    pub dc: u16,
    pub media: bool,
    pub test: bool,
    pub label: &'a str,
    /// SOCKS5 mode: the endpoint the client asked for (used for the Worker `dst`
    /// and the raw-TCP fallback). `None` in MTProto-proxy mode.
    pub orig_dst: Option<(Ipv4Addr, u16)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    Direct,
    CfWorker,
    CfProxy,
    Tcp,
}

pub enum Route {
    Ws {
        conn: WsConn,
        kind: RouteKind,
        /// The far end is Telegram's WS gateway, which wants exactly one MTProto
        /// transport packet per frame. (A Worker is a raw TCP pipe: no framing.)
        framed: bool,
    },
    Tcp(TcpStream),
}

#[derive(Default)]
struct RouteState {
    ws_blacklist: HashSet<DcKey>,
    dc_fail_until: HashMap<DcKey, Instant>,
    ip_fail_until: HashMap<Ipv4Addr, Instant>,
    /// `worker:<domain>` / `cf:<dc>:<domain>` -> do not try before this instant.
    leg_fail_until: HashMap<String, Instant>,
}

pub struct Router {
    pub cfg: Arc<Settings>,
    pub tls: Arc<TlsConfigs>,
    pub stats: Arc<Stats>,
    pub connector: Arc<DirectConnector>,
    pub pool: Arc<WsPool>,
    pub cf_pool: Arc<CfWorkerPool>,
    pub balancer: Arc<Balancer>,
    state: Mutex<RouteState>,
}

impl Router {
    pub fn new(cfg: Arc<Settings>, stats: Arc<Stats>) -> anyhow::Result<Arc<Self>> {
        let tls = Arc::new(build_tls_configs(cfg.skip_tls_verify)?);
        Ok(Self::with_tls(cfg, stats, tls))
    }

    pub fn with_tls(cfg: Arc<Settings>, stats: Arc<Stats>, tls: Arc<TlsConfigs>) -> Arc<Self> {
        let connector = DirectConnector::new(cfg.clone(), tls.clone(), stats.clone());
        let pool = WsPool::new(cfg.clone(), stats.clone(), connector.clone());
        let cf_pool = CfWorkerPool::new(cfg.clone(), tls.clone(), stats.clone());
        let balancer = Arc::new(Balancer::new());
        if cfg.fallback_cfproxy {
            balancer.init(&cfg.cfproxy_user_domains);
        }
        Arc::new(Self { cfg, tls, stats, connector, pool, cf_pool, balancer, state: Mutex::new(RouteState::default()) })
    }

    /// Start pool warm-up and (unless the user supplied their own domains) the
    /// periodic refresh of the Cloudflare domain pool.
    pub fn start_background(self: &Arc<Self>) {
        self.pool.warmup();
        self.cf_pool.warmup();
        if self.cfg.fallback_cfproxy && self.cfg.cfproxy_user_domains.is_empty() {
            self.balancer.spawn_refresh(self.tls.clone(), self.cfg.upstream_socks5.clone());
        }
    }

    /// Names of DCs currently blacklisted for WS (stats line).
    pub fn blacklist_summary(&self) -> String {
        let s = self.state.lock().unwrap();
        if s.ws_blacklist.is_empty() {
            return "none".into();
        }
        let mut v: Vec<String> = s.ws_blacklist.iter().map(|k| k.to_string()).collect();
        v.sort();
        v.join(", ")
    }

    fn leg_cooling(&self, key: &str) -> bool {
        let s = self.state.lock().unwrap();
        s.leg_fail_until.get(key).is_some_and(|u| Instant::now() < *u)
    }

    fn leg_failed(&self, key: String) {
        self.state.lock().unwrap().leg_fail_until.insert(key, Instant::now() + LEG_FAIL_COOLDOWN);
    }

    fn leg_ok(&self, key: &str) {
        self.state.lock().unwrap().leg_fail_until.remove(key);
    }

    fn cf_available(&self, test: bool) -> bool {
        !self.cfg.cfproxy_worker_domains.is_empty() || (self.cfg.fallback_cfproxy && !test)
    }

    /// Open the best available route for `req`.
    pub async fn connect(&self, req: &Request<'_>) -> Option<Route> {
        let key = DcKey { dc: req.dc, media: req.media, test: req.test };
        let target = self.cfg.dc_ip(req.dc);
        let now = Instant::now();
        let (blacklisted, ip_failed, dc_failing) = {
            let s = self.state.lock().unwrap();
            (
                s.ws_blacklist.contains(&key),
                target.is_some_and(|t| s.ip_fail_until.get(&t).is_some_and(|u| now < *u)),
                s.dc_fail_until.get(&key).is_some_and(|u| now < *u),
            )
        };

        let mut direct: Option<WsConn> = None;
        match target {
            None => debug!("[{}] {} has no direct route -> fallback", req.label, key),
            Some(_) if blacklisted => debug!("[{}] {} WS blacklisted -> fallback", req.label, key),
            Some(t) if ip_failed && self.cf_available(req.test) => {
                // The gateway timed out recently. It may have been accidental, so
                // a connection that is already pooled is still worth using.
                if !req.test {
                    direct = self.pool.get((req.dc, req.media), t).await;
                }
                if direct.is_some() {
                    info!("[{}] {} gateway in cooldown, but pool hit -> using WS", req.label, key);
                } else {
                    info!("[{}] {} gateway {} timed out recently -> fallback", req.label, key, t);
                }
            }
            Some(t) => direct = self.try_direct(req, key, t, dc_failing).await,
        }

        if let Some(conn) = direct {
            if let Some(t) = target {
                self.note_direct_ok(key, t);
            }
            self.stats.ws.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some(Route::Ws { conn, kind: RouteKind::Direct, framed: true });
        }
        self.fallback(req, key).await
    }

    fn note_direct_ok(&self, key: DcKey, target: Ipv4Addr) {
        let mut s = self.state.lock().unwrap();
        s.ip_fail_until.remove(&target);
        s.dc_fail_until.remove(&key);
        drop(s);
        if !key.test {
            self.pool.report_success((key.dc, key.media));
        }
    }

    async fn try_direct(&self, req: &Request<'_>, key: DcKey, target: Ipv4Addr, dc_failing: bool) -> Option<WsConn> {
        use std::sync::atomic::Ordering::Relaxed;
        let path = if req.test { WS_PATH_TEST } else { WS_PATH };
        let timeout = if dc_failing { WS_FAIL_TIMEOUT } else { self.cfg.connect_timeout };

        if !req.test {
            if let Some(c) = self.pool.get((req.dc, req.media), target).await {
                info!("[{}] {} -> pool hit via {}", req.label, key, target);
                return Some(c);
            }
        }

        let mut any_redirect = false;
        let mut all_redirects = true;
        let mut timed_out = false;
        for domain in ws_domains(req.dc, req.media) {
            info!("[{}] {} -> wss://{}{} via {}", req.label, key, domain, path, target);
            match self.connector.connect(target, &domain, path, timeout).await {
                Ok(c) => return Some(c),
                Err(e) if e.is_redirect() => {
                    self.stats.ws_errors.fetch_add(1, Relaxed);
                    any_redirect = true;
                    warn!(
                        "[{}] {} got a redirect from {} -> {}",
                        req.label,
                        key,
                        domain,
                        e.redirect_location().unwrap_or("?")
                    );
                }
                Err(e) if e.is_timeout() => {
                    self.stats.ws_errors.fetch_add(1, Relaxed);
                    timed_out = true;
                    all_redirects = false;
                    warn!("[{}] {} WS connect timed out via {}", req.label, key, domain);
                    break;
                }
                Err(e) => {
                    self.stats.ws_errors.fetch_add(1, Relaxed);
                    all_redirects = false;
                    warn!("[{}] {} WS connect failed: {}", req.label, key, e);
                }
            }
        }

        let now = Instant::now();
        let mut s = self.state.lock().unwrap();
        if timed_out && !dc_failing {
            s.ip_fail_until.insert(target, now + IP_FAIL_COOLDOWN);
            info!("[{}] {} gateway {} timed out, cooldown {}s", req.label, key, target, IP_FAIL_COOLDOWN.as_secs());
        }
        if any_redirect && all_redirects {
            s.ws_blacklist.insert(key);
            warn!("[{}] {} blacklisted for WS (all redirects)", req.label, key);
        } else {
            s.dc_fail_until.insert(key, now + DC_FAIL_COOLDOWN);
            info!("[{}] {} WS failed, fallback chain for {}s", req.label, key, DC_FAIL_COOLDOWN.as_secs());
        }
        None
    }

    async fn fallback(&self, req: &Request<'_>, key: DcKey) -> Option<Route> {
        use std::sync::atomic::Ordering::Relaxed;
        let dst: Option<(Ipv4Addr, u16)> = req.orig_dst.or_else(|| dc_default_ip(req.dc, req.test).map(|ip| (ip, 443)));

        if let Some((dst_ip, _)) = dst {
            if !self.cfg.cfproxy_worker_domains.is_empty() {
                if let Some(conn) = self.try_worker(req, key, dst_ip).await {
                    self.stats.cf_worker.fetch_add(1, Relaxed);
                    return Some(Route::Ws { conn, kind: RouteKind::CfWorker, framed: false });
                }
            }
        }
        if self.cfg.fallback_cfproxy && !req.test && !self.balancer.is_empty() {
            if let Some(conn) = self.try_cf_proxy(req, key).await {
                self.stats.cf_proxy.fetch_add(1, Relaxed);
                return Some(Route::Ws { conn, kind: RouteKind::CfProxy, framed: true });
            }
        }
        if let Some((ip, port)) = dst {
            info!("[{}] {} -> TCP fallback to {}:{}", req.label, key, ip, port);
            let target = Target::Addr(SocketAddr::new(ip.into(), port));
            let up = self.cfg.upstream_socks5.as_deref();
            match tokio::time::timeout(FALLBACK_TIMEOUT, crate::upstream::connect(&target, up)).await {
                Ok(Ok(s)) => {
                    tune_socket(&s, self.cfg.buffer_size);
                    self.stats.tcp_fallback.fetch_add(1, Relaxed);
                    return Some(Route::Tcp(s));
                }
                Ok(Err(e)) => warn!("[{}] TCP fallback to {}:{} failed: {}", req.label, ip, port, e),
                Err(_) => warn!("[{}] TCP fallback to {}:{} timed out", req.label, ip, port),
            }
        }
        warn!("[{}] {} no route available", req.label, key);
        None
    }

    async fn try_worker(&self, req: &Request<'_>, key: DcKey, dst: Ipv4Addr) -> Option<WsConn> {
        if !req.test {
            if let Some((conn, domain)) = self.cf_pool.get(req.dc, dst).await {
                info!("[{}] {} -> CF worker pool hit via {} for {}", req.label, key, domain, dst);
                return Some(conn);
            }
        }
        let mut skipped = 0;
        for domain in self.cf_pool.available_domains() {
            let leg = format!("worker:{}", domain.to_ascii_lowercase());
            if self.leg_cooling(&leg) {
                skipped += 1;
                continue;
            }
            info!("[{}] {} -> trying CF worker {} for {}", req.label, key, domain, dst);
            match self.cf_pool.connect(&domain, dst, req.dc, FALLBACK_TIMEOUT).await {
                Ok(c) => {
                    self.leg_ok(&leg);
                    return Some(c);
                }
                Err(e) => {
                    self.leg_failed(leg);
                    warn!("[{}] {} CF worker {} failed: {}", req.label, key, domain, e);
                }
            }
        }
        if skipped > 0 {
            debug!("[{}] {} {} CF worker(s) skipped: failed recently", req.label, key, skipped);
        }
        None
    }

    /// Race Cloudflare domains in small waves; the first to complete the upgrade
    /// wins and is remembered for this DC.
    async fn try_cf_proxy(&self, req: &Request<'_>, key: DcKey) -> Option<WsConn> {
        info!("[{}] {} -> trying CF proxy", req.label, key);
        let leg = |base: &str| format!("cf:{}:{}", req.dc, base.to_ascii_lowercase());
        let candidates: Vec<String> =
            self.balancer.domains_for_dc(req.dc).into_iter().filter(|b| !self.leg_cooling(&leg(b))).collect();
        if candidates.is_empty() {
            debug!("[{}] {} every CF domain failed recently", req.label, key);
        }
        for wave in candidates.chunks(CF_WAVE).take(CF_WAVES) {
            let mut set = JoinSet::new();
            for base in wave {
                let (cfg, tls, base, dc) = (self.cfg.clone(), self.tls.clone(), base.clone(), req.dc);
                set.spawn(async move {
                    let domain = format!("kws{dc}.{base}");
                    let res = connect_named(&cfg, &tls, &domain, WS_PATH, FALLBACK_TIMEOUT).await;
                    (base, res)
                });
            }
            while let Some(r) = set.join_next().await {
                match r {
                    Ok((base, Ok(conn))) => {
                        set.abort_all();
                        self.leg_ok(&leg(&base));
                        if self.balancer.update_domain_for_dc(req.dc, &base) {
                            info!("[{}] switched active CF domain", req.label);
                        }
                        return Some(conn);
                    }
                    Ok((base, Err(e))) => {
                        self.leg_failed(leg(&base));
                        warn!("[{}] {} CF proxy failed: {}", req.label, key, e);
                    }
                    Err(_) => {}
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc_key_display() {
        assert_eq!(DcKey { dc: 2, media: false, test: false }.to_string(), "DC2");
        assert_eq!(DcKey { dc: 4, media: true, test: false }.to_string(), "DC4m");
        assert_eq!(DcKey { dc: 2, media: true, test: true }.to_string(), "DC2tm");
    }

    #[test]
    fn cf_availability() {
        let mut cfg = Settings::default();
        let r = |c: Settings| {
            Router::with_tls(Arc::new(c), Arc::new(Stats::new()), Arc::new(build_tls_configs(false).unwrap()))
        };
        cfg.fallback_cfproxy = false;
        assert!(!r(cfg.clone()).cf_available(false));
        cfg.cfproxy_worker_domains = vec!["w.example".into()];
        assert!(r(cfg.clone()).cf_available(true), "workers also serve test DCs");
        cfg.cfproxy_worker_domains.clear();
        cfg.fallback_cfproxy = true;
        assert!(r(cfg.clone()).cf_available(false));
        assert!(!r(cfg).cf_available(true), "CF proxy domains never serve test DCs");
    }
}
