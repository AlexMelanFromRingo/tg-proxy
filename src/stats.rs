use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

#[derive(Default)]
pub struct Stats {
    pub total: AtomicU64,
    pub active: AtomicU64,
    /// Connections bridged over a direct WebSocket to Telegram.
    pub ws: AtomicU64,
    pub tcp_fallback: AtomicU64,
    pub cf_proxy: AtomicU64,
    pub cf_worker: AtomicU64,
    /// Direct connections that needed SNI fronting.
    pub fronting: AtomicU64,
    /// Bad MTProto handshakes (wrong secret / not MTProto).
    pub bad: AtomicU64,
    /// Fake-TLS probes forwarded to the masking domain.
    pub masked: AtomicU64,
    pub ws_errors: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub pool_hits: AtomicU64,
    pub pool_misses: AtomicU64,
    pub cf_pool_hits: AtomicU64,
    pub cf_pool_misses: AtomicU64,
    /// SOCKS5 connections to non-Telegram hosts.
    pub passthrough: AtomicU64,
    pub http_rejected: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts a live client connection for as long as the guard exists.
    pub fn enter(self: &Arc<Self>) -> ActiveGuard {
        self.total.fetch_add(1, Relaxed);
        self.active.fetch_add(1, Relaxed);
        ActiveGuard(Arc::clone(self))
    }

    pub fn summary(&self) -> String {
        let ratio = |h: &AtomicU64, m: &AtomicU64| {
            let (h, m) = (h.load(Relaxed), m.load(Relaxed));
            if h + m == 0 {
                "n/a".to_string()
            } else {
                format!("{}/{}", h, h + m)
            }
        };
        format!(
            "total={} active={} ws={} front={} cf_worker={} cf_proxy={} tcp_fb={} bad={} masked={} err={} pool={} cf_pool={} up={} down={}",
            self.total.load(Relaxed),
            self.active.load(Relaxed),
            self.ws.load(Relaxed),
            self.fronting.load(Relaxed),
            self.cf_worker.load(Relaxed),
            self.cf_proxy.load(Relaxed),
            self.tcp_fallback.load(Relaxed),
            self.bad.load(Relaxed),
            self.masked.load(Relaxed),
            self.ws_errors.load(Relaxed),
            ratio(&self.pool_hits, &self.pool_misses),
            ratio(&self.cf_pool_hits, &self.cf_pool_misses),
            human_bytes(self.bytes_up.load(Relaxed)),
            human_bytes(self.bytes_down.load(Relaxed)),
        )
    }
}

pub struct ActiveGuard(Arc<Stats>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Relaxed);
    }
}

pub fn human_bytes(n: u64) -> String {
    let mut v = n as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if v < 1024.0 {
            return format!("{:.1}{}", v, unit);
        }
        v /= 1024.0;
    }
    format!("{:.1}TB", v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_formats() {
        assert_eq!(human_bytes(0), "0.0B");
        assert_eq!(human_bytes(1536), "1.5KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0MB");
    }

    #[test]
    fn active_guard_counts() {
        let s = Arc::new(Stats::new());
        {
            let _a = s.enter();
            let _b = s.enter();
            assert_eq!(s.active.load(Relaxed), 2);
        }
        assert_eq!(s.active.load(Relaxed), 0);
        assert_eq!(s.total.load(Relaxed), 2);
        assert!(s.summary().contains("pool=n/a"));
    }
}
