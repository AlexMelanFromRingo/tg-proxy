use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    /// DC ID (1-5) -> target IP to connect to via WebSocket
    pub dc_ips: HashMap<u8, Ipv4Addr>,
    pub pool_size: usize,
    pub pool_max_age: Duration,
    pub skip_tls_verify: bool,
    pub connect_timeout: Duration,
}

impl Config {
    pub fn dc_ip(&self, dc: u8) -> Option<Ipv4Addr> {
        self.dc_ips.get(&dc).copied()
    }
}
