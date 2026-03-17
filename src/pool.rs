use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use rustls::ClientConfig;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::config::Config;
use crate::websocket::{self, TlsStream};

pub type DcKey = (u8, bool); // (dc_id, is_media)

struct PoolEntry {
    stream: TlsStream,
    created: Instant,
}

#[derive(Default)]
struct PoolInner {
    idle: HashMap<DcKey, VecDeque<PoolEntry>>,
    refilling: HashSet<DcKey>,
}

pub struct WsPool {
    inner: Mutex<PoolInner>,
}

impl WsPool {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(PoolInner::default()),
        }
    }

    /// Get a ready WebSocket TLS stream from the pool.
    /// Returns `None` if no pre-warmed connection is available.
    /// Schedules a background refill regardless.
    pub async fn get(
        self: &Arc<Self>,
        key: DcKey,
        target_ip: Ipv4Addr,
        domains: &[String; 2],
        config: &Config,
        tls: Arc<ClientConfig>,
    ) -> Option<TlsStream> {
        let max_age = config.pool_max_age;
        let pool_size = config.pool_size;
        let connect_timeout = config.connect_timeout;

        let result = {
            let mut inner = self.inner.lock().await;
            let bucket = inner.idle.entry(key).or_default();

            // Pop entries until we find a live, non-expired connection
            let mut found = None;
            while let Some(entry) = bucket.pop_front() {
                if entry.created.elapsed() > max_age {
                    debug!("Pool: discarding expired entry for DC{}{}", key.0, if key.1 { "m" } else { "" });
                    continue;
                }
                found = Some(entry.stream);
                break;
            }

            let should_refill = !inner.refilling.contains(&key)
                && inner.idle.get(&key).map(|b| b.len()).unwrap_or(0) < pool_size;

            if should_refill {
                inner.refilling.insert(key);
            }

            (found, should_refill)
        };

        let (found, should_refill) = result;

        if should_refill {
            let pool = Arc::clone(self);
            let domains = domains.clone();
            tokio::spawn(async move {
                pool.refill(key, target_ip, &domains, pool_size, connect_timeout, tls).await;
            });
        }

        found
    }

    async fn refill(
        self: &Arc<Self>,
        key: DcKey,
        target_ip: Ipv4Addr,
        domains: &[String; 2],
        pool_size: usize,
        connect_timeout: std::time::Duration,
        tls: Arc<ClientConfig>,
    ) {
        let needed = {
            let inner = self.inner.lock().await;
            let current = inner.idle.get(&key).map(|b| b.len()).unwrap_or(0);
            pool_size.saturating_sub(current)
        };

        let mut new_entries = Vec::with_capacity(needed);
        // Connect in parallel
        let tasks: Vec<_> = (0..needed)
            .map(|_| {
                let domains = domains.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    connect_for_pool(target_ip, &domains, connect_timeout, tls).await
                })
            })
            .collect();

        for task in tasks {
            if let Ok(Some(stream)) = task.await {
                new_entries.push(PoolEntry {
                    stream,
                    created: Instant::now(),
                });
            }
        }

        let added = new_entries.len();
        let mut inner = self.inner.lock().await;
        let total = {
            let bucket = inner.idle.entry(key).or_default();
            bucket.extend(new_entries);
            bucket.len()
        };
        inner.refilling.remove(&key);

        debug!(
            "Pool refilled DC{}{}: +{} total={}",
            key.0,
            if key.1 { "m" } else { "" },
            added,
            total
        );
    }

    /// Pre-fill the pool for all configured DCs at startup.
    pub async fn warmup(self: &Arc<Self>, config: &Config, tls: Arc<ClientConfig>) {
        let dc_ips: Vec<_> = config.dc_ips.iter().map(|(&dc, &ip)| (dc, ip)).collect();
        let pool_size = config.pool_size;
        let connect_timeout = config.connect_timeout;

        for (dc, ip) in dc_ips {
            for is_media in [false, true] {
                let key = (dc, is_media);
                {
                    let mut inner = self.inner.lock().await;
                    if inner.refilling.contains(&key) {
                        continue;
                    }
                    inner.refilling.insert(key);
                }
                let pool = Arc::clone(self);
                let domains = crate::ip_map::ws_domains(dc, is_media);
                let tls = tls.clone();
                tokio::spawn(async move {
                    pool.refill(key, ip, &domains, pool_size, connect_timeout, tls).await;
                });
            }
        }
        tracing::info!("WS pool warmup started for {} DCs", config.dc_ips.len());
    }
}

async fn connect_for_pool(
    ip: Ipv4Addr,
    domains: &[String; 2],
    connect_timeout: std::time::Duration,
    tls: Arc<ClientConfig>,
) -> Option<TlsStream> {
    for domain in domains {
        match websocket::connect(ip, domain, tls.clone(), connect_timeout).await {
            Ok(stream) => return Some(stream),
            Err(e) if e.is_redirect() => continue,
            Err(e) => {
                warn!("Pool pre-connect {} failed: {}", domain, e);
                return None;
            }
        }
    }
    None
}
