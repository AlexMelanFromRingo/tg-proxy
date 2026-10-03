//! tg-proxy: a Telegram proxy that tunnels MTProto over WebSocket.
//!
//! Layers, from the client inwards:
//!
//! * front-ends — [`mtproxy`] (MTProto proxy, optional fake TLS) and [`socks5`];
//! * [`route`] — picks how to reach the datacenter (direct WS, SNI fronting,
//!   Cloudflare Worker, Cloudflare domains, raw TCP) and remembers failures;
//! * [`bridge`] — pumps bytes, re-encrypting with [`crypto`] where needed.

pub mod app;
pub mod balancer;
pub mod bridge;
pub mod check;
pub mod client;
pub mod config;
pub mod crypto;
pub mod fake_tls;
pub mod ip_map;
pub mod logging;
pub mod mtproxy;
pub mod pool;
pub mod route;
pub mod socks5;
pub mod stats;
pub mod upstream;
pub mod websocket;
