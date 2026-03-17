use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Stats {
    pub total: AtomicU64,
    pub ws: AtomicU64,
    pub tcp_fallback: AtomicU64,
    pub http_rejected: AtomicU64,
    pub passthrough: AtomicU64,
    pub ws_errors: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub pool_hits: AtomicU64,
    pub pool_misses: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn summary(&self) -> String {
        let hits = self.pool_hits.load(Ordering::Relaxed);
        let misses = self.pool_misses.load(Ordering::Relaxed);
        format!(
            "total={} ws={} tcp_fb={} http_skip={} pass={} err={} \
             pool={}/{} up={} down={}",
            self.total.load(Ordering::Relaxed),
            self.ws.load(Ordering::Relaxed),
            self.tcp_fallback.load(Ordering::Relaxed),
            self.http_rejected.load(Ordering::Relaxed),
            self.passthrough.load(Ordering::Relaxed),
            self.ws_errors.load(Ordering::Relaxed),
            hits,
            hits + misses,
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed)),
        )
    }
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut val = n as f64;
    let mut idx = 0;
    while val >= 1024.0 && idx < UNITS.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    format!("{:.1}{}", val, UNITS[idx])
}
