//! `tg-proxy --check`: test every route to Telegram from this machine.
//!
//! Each probe performs a real MTProto exchange — an unencrypted `req_pq_multi`
//! that a datacenter answers with `resPQ` — so a ✔ means "Telegram answered
//! through this route", not merely "a socket opened". Run it on the network that
//! has the problem to see which routes survive there.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cipher::StreamCipher;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::balancer::Balancer;
use crate::config::Settings;
use crate::crypto::{generate_relay_init, upstream_ciphers, Aes256Ctr, PROTO_ABRIDGED};
use crate::fake_tls::unix_now;
use crate::ip_map::{ws_domains, DC_DEFAULT_IPS};
use crate::logging::censor_line;
use crate::pool::{connect_named, worker_path, WS_PATH};
use crate::route::DcKey;
use crate::websocket::{build_tls_configs, connect, ConnectOpts, Target, TlsConfigs, WsConn};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;
const RES_PQ: [u8; 4] = [0x63, 0x24, 0x16, 0x05]; // resPQ#05162463, little-endian

// ── The MTProto exchange ──────────────────────────────────────────────────────

/// One `req_pq_multi` → `resPQ` exchange over the abridged transport.
pub struct Probe {
    /// 64-byte obfuscated2 init: the first thing sent on a fresh connection.
    pub init: [u8; 64],
    /// The encrypted request packet (send right after `init`).
    pub request: Vec<u8>,
    nonce: [u8; 16],
    dec: Aes256Ctr,
    buf: Vec<u8>,
}

impl Probe {
    pub fn new(dc: u16) -> Self {
        let init = generate_relay_init(PROTO_ABRIDGED, dc as i16);
        let (mut enc, dec) = upstream_ciphers(&init);
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);

        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&[0u8; 8]); // auth_key_id: none (unencrypted message)
        let msg_id = (unix_now() << 32) | (rng.next_u32() as u64 & 0xFFFF_FFFC);
        body.extend_from_slice(&msg_id.to_le_bytes());
        body.extend_from_slice(&20u32.to_le_bytes()); // message_data_length
        body.extend_from_slice(&REQ_PQ_MULTI.to_le_bytes());
        body.extend_from_slice(&nonce);

        let mut request = vec![(body.len() / 4) as u8]; // abridged: length in words
        request.extend_from_slice(&body);
        enc.apply_keystream(&mut request);
        Self { init, request, nonce, dec, buf: Vec::new() }
    }

    /// Feed bytes received from the server. `Ok(true)` once a complete, valid
    /// `resPQ` for our nonce has arrived.
    pub fn feed(&mut self, data: &[u8]) -> Result<bool, String> {
        let mut d = data.to_vec();
        self.dec.apply_keystream(&mut d);
        self.buf.extend_from_slice(&d);

        let Some(&first) = self.buf.first() else { return Ok(false) };
        let (header, len) = if first == 0x7F {
            if self.buf.len() < 4 {
                return Ok(false);
            }
            (4, u32::from_le_bytes([self.buf[1], self.buf[2], self.buf[3], 0]) as usize * 4)
        } else {
            (1, (first & 0x7F) as usize * 4)
        };
        if len == 4 {
            // A bare 4-byte payload is a transport-level error code (e.g. -404).
            if self.buf.len() < header + 4 {
                return Ok(false);
            }
            let code = i32::from_le_bytes(self.buf[header..header + 4].try_into().unwrap());
            return Err(format!("Telegram answered with transport error {code}"));
        }
        if self.buf.len() < header + len {
            return Ok(false);
        }
        let p = &self.buf[header..header + len];
        if p.len() < 40 || p[20..24] != RES_PQ {
            return Err("unexpected reply (not resPQ)".into());
        }
        if p[24..40] != self.nonce {
            return Err("reply does not match our nonce".into());
        }
        Ok(true)
    }
}

/// Probe over an established WebSocket (gateway, Cloudflare domain or Worker).
pub async fn probe_ws(mut conn: WsConn, dc: u16) -> Result<(), String> {
    let mut probe = Probe::new(dc);
    let (init, request) = (probe.init, probe.request.clone());
    conn.send(&init).await.map_err(|e| format!("send: {e}"))?;
    conn.send(&request).await.map_err(|e| format!("send: {e}"))?;
    loop {
        match conn.recv().await {
            Ok(Some(data)) => {
                if probe.feed(&data)? {
                    return Ok(());
                }
            }
            Ok(None) => return Err("connection closed by the peer".into()),
            Err(e) => return Err(format!("receive: {e}")),
        }
    }
}

/// Probe over a raw TCP stream (straight to a datacenter).
pub async fn probe_tcp(mut s: tokio::net::TcpStream, dc: u16) -> Result<(), String> {
    let mut probe = Probe::new(dc);
    let mut out = probe.init.to_vec();
    out.extend_from_slice(&probe.request);
    s.write_all(&out).await.map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => return Err("connection closed by the peer".into()),
            Ok(n) => {
                if probe.feed(&buf[..n])? {
                    return Ok(());
                }
            }
            Err(e) => return Err(format!("receive: {e}")),
        }
    }
}

// ── Probe plan ────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum Kind {
    Direct { dc: u16, ip: Ipv4Addr, fronted: bool },
    Worker { domain: String, dc: u16, dst: Ipv4Addr },
    CfProxy { base: String, dc: u16 },
    Tcp { dc: u16, ip: Ipv4Addr },
}

impl Kind {
    fn group(&self) -> usize {
        match self {
            Kind::Direct { .. } => 0,
            Kind::Worker { .. } => 1,
            Kind::CfProxy { .. } => 2,
            Kind::Tcp { .. } => 3,
        }
    }

    fn dc(&self) -> u16 {
        match self {
            Kind::Direct { dc, .. } | Kind::Worker { dc, .. } | Kind::CfProxy { dc, .. } | Kind::Tcp { dc, .. } => *dc,
        }
    }

    fn route_name(&self) -> &'static str {
        match self {
            Kind::Direct { fronted: false, .. } => "direct",
            Kind::Direct { fronted: true, .. } => "fronted",
            Kind::Worker { .. } => "worker",
            Kind::CfProxy { .. } => "cf-proxy",
            Kind::Tcp { .. } => "tcp",
        }
    }

    fn describe(&self, cfg: &Settings) -> String {
        let dc = DcKey { dc: self.dc(), media: false, test: false };
        match self {
            Kind::Direct { dc: d, fronted: false, .. } => {
                format!("{dc:<4} plain SNI ({})", ws_domains(*d, false)[0])
            }
            Kind::Direct { fronted: true, .. } => format!("{dc:<4} SNI fronting ({})", cfg.fronting_sni),
            Kind::Worker { domain, .. } => format!("{dc:<4} via {domain}"),
            Kind::CfProxy { base, dc: d } => format!("DC{d:<2} via kws{d}.{base}"),
            Kind::Tcp { ip, .. } => format!("{dc:<4} {ip}:443"),
        }
    }
}

const GROUPS: [&str; 4] = [
    "Direct WebSocket to Telegram's gateway",
    "Cloudflare Worker",
    "Cloudflare-proxied domains",
    "Raw TCP to the datacenters",
];

async fn run_probe(cfg: Arc<Settings>, tls: Arc<TlsConfigs>, kind: Kind) -> Result<(), String> {
    let work = async {
        match &kind {
            Kind::Direct { dc, ip, fronted } => {
                let domain = ws_domains(*dc, false)[0].clone();
                let addr = SocketAddr::new((*ip).into(), cfg.gateway_port);
                let mut o = ConnectOpts::new(Target::Addr(addr), domain, WS_PATH, PROBE_TIMEOUT);
                o.upstream = cfg.upstream_socks5.clone();
                if *fronted {
                    o.sni = Some(cfg.fronting_sni.clone());
                    o.fronted = true;
                }
                let conn = connect(&tls, &o).await.map_err(|e| e.to_string())?;
                probe_ws(conn, *dc).await
            }
            Kind::Worker { domain, dc, dst } => {
                let conn = connect_named(&cfg, &tls, domain, &worker_path(*dst, *dc), PROBE_TIMEOUT)
                    .await
                    .map_err(|e| e.to_string())?;
                probe_ws(conn, *dc).await
            }
            Kind::CfProxy { base, dc } => {
                let domain = format!("kws{dc}.{base}");
                let conn =
                    connect_named(&cfg, &tls, &domain, WS_PATH, PROBE_TIMEOUT).await.map_err(|e| e.to_string())?;
                probe_ws(conn, *dc).await
            }
            Kind::Tcp { dc, ip } => {
                let target = Target::Addr(SocketAddr::new((*ip).into(), 443));
                let s = crate::upstream::connect(&target, cfg.upstream_socks5.as_deref())
                    .await
                    .map_err(|e| e.to_string())?;
                probe_tcp(s, *dc).await
            }
        }
    };
    timeout(PROBE_TIMEOUT, work).await.unwrap_or_else(|_| Err("timeout".into()))
}

async fn plan(cfg: &Settings, tls: &TlsConfigs) -> Vec<Kind> {
    let mut v = Vec::new();

    let mut direct: Vec<_> = cfg.dc_redirects.iter().collect();
    direct.sort();
    for (&dc, &ip) in direct {
        v.push(Kind::Direct { dc, ip, fronted: false });
        if !cfg.fronting_sni.is_empty() {
            v.push(Kind::Direct { dc, ip, fronted: true });
        }
    }

    for domain in &cfg.cfproxy_worker_domains {
        for &(dc, dst) in DC_DEFAULT_IPS {
            v.push(Kind::Worker { domain: domain.clone(), dc, dst });
        }
    }

    if cfg.fallback_cfproxy {
        let balancer = Balancer::new();
        balancer.init(&cfg.cfproxy_user_domains);
        if cfg.cfproxy_user_domains.is_empty() {
            // Same download the proxy does at start-up (best effort).
            balancer.refresh_once(tls, cfg.upstream_socks5.as_deref()).await;
            for base in balancer.domains_for_dc(2).into_iter().take(6) {
                v.push(Kind::CfProxy { base, dc: 2 });
            }
        } else {
            for base in &cfg.cfproxy_user_domains {
                for &(dc, _) in DC_DEFAULT_IPS {
                    v.push(Kind::CfProxy { base: base.clone(), dc });
                }
            }
        }
    }

    for &(dc, ip) in DC_DEFAULT_IPS {
        v.push(Kind::Tcp { dc, ip });
    }
    v
}

// ── Report ────────────────────────────────────────────────────────────────────

fn use_color() -> bool {
    std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && (!cfg!(windows) || std::env::var_os("WT_SESSION").is_some())
}

pub async fn run(cfg: Settings) -> anyhow::Result<()> {
    let tls = Arc::new(build_tls_configs(cfg.skip_tls_verify)?);
    let cfg = Arc::new(cfg);

    let color = use_color();
    let paint = |code: &str, s: &str| if color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() };
    let (bold, dim, green, red, yellow) = (
        |s: &str| paint("1", s),
        |s: &str| paint("2", s),
        |s: &str| paint("32", s),
        |s: &str| paint("31", s),
        |s: &str| paint("33", s),
    );

    println!("\n  {}", bold("tg-proxy route check"));
    println!("  {}", dim("A real MTProto handshake (req_pq) with Telegram, through every route.\n"));
    if let Some(up) = &cfg.upstream_socks5 {
        println!("  {}\n", dim(&format!("All probes go through the upstream SOCKS5 proxy {up}")));
    }

    let kinds = plan(&cfg, &tls).await;
    println!("  {}\n", dim(&format!("Probing {} routes (up to {} s)…", kinds.len(), PROBE_TIMEOUT.as_secs())));

    let mut set = JoinSet::new();
    for (i, kind) in kinds.iter().cloned().enumerate() {
        let (cfg, tls) = (cfg.clone(), tls.clone());
        set.spawn(async move {
            let t = Instant::now();
            let r = run_probe(cfg, tls, kind).await;
            (i, r.map(|_| t.elapsed()))
        });
    }
    let mut results: Vec<Option<Result<Duration, String>>> = vec![None; kinds.len()];
    while let Some(r) = set.join_next().await {
        if let Ok((i, res)) = r {
            results[i] = Some(res);
        }
    }

    // dc -> working routes
    let mut covered: BTreeMap<u16, Vec<&'static str>> = BTreeMap::new();
    for &(dc, _) in DC_DEFAULT_IPS {
        covered.entry(dc).or_default();
    }

    for (g, title) in GROUPS.iter().enumerate() {
        let rows: Vec<usize> = (0..kinds.len()).filter(|&i| kinds[i].group() == g).collect();
        if rows.is_empty() {
            continue;
        }
        println!("  {}", bold(title));
        for i in rows {
            let name = censor_line(&kinds[i].describe(&cfg));
            match results[i].as_ref().unwrap() {
                Ok(d) => {
                    println!("    {} {:<56} {}", green("✔"), name, dim(&format!("{} ms", d.as_millis())));
                    let routes = covered.entry(kinds[i].dc()).or_default();
                    if !routes.contains(&kinds[i].route_name()) {
                        routes.push(kinds[i].route_name());
                    }
                }
                Err(e) => println!("    {} {:<56} {}", red("✘"), name, dim(&censor_line(e))),
            }
        }
        println!();
    }

    println!("  {}", bold("Datacenters"));
    let mut missing = Vec::new();
    for (dc, routes) in &covered {
        if routes.is_empty() {
            println!("    {} DC{:<4} {}", red("✘"), dc, dim("no working route"));
            missing.push(*dc);
        } else {
            println!("    {} DC{:<4} {}", green("✔"), dc, routes.join(", "));
        }
    }
    println!();

    if missing.is_empty() {
        println!("  {}", green("Every datacenter is reachable: Telegram should work through this proxy."));
    } else if missing.len() < covered.len() {
        let list: Vec<String> = missing.iter().map(|d| format!("DC{d}")).collect();
        println!(
            "  {}",
            yellow(&format!(
                "No route for {}: accounts living on those datacenters will not connect.",
                list.join(", ")
            ))
        );
        println!("  {}", dim("Add a Cloudflare Worker (docs/CLOUDFLARE.md) with --cfproxy-worker-domain,"));
        println!("  {}", dim("or send everything through an existing tunnel with --upstream-socks5."));
    } else {
        println!("  {}", red("Nothing reaches Telegram from here."));
        println!("  {}", dim("Set up a Cloudflare Worker (docs/CLOUDFLARE.md) and pass --cfproxy-worker-domain,"));
        println!("  {}", dim("or use an existing tunnel with --upstream-socks5. If every probe fails with"));
        println!("  {}", dim("'timeout', the whole machine may be offline or behind a captive portal."));
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a datacenter does: decrypt the client's stream, answer with resPQ.
    fn server_reply(probe: &Probe, tamper_nonce: bool) -> Vec<u8> {
        let (mut srv_dec, mut srv_enc) = upstream_ciphers(&probe.init);
        let mut req = probe.request.clone();
        srv_dec.apply_keystream(&mut req);
        assert_eq!(req[0], 10, "abridged length prefix: 40 bytes = 10 words");
        assert_eq!(&req[1..9], &[0u8; 8], "auth_key_id is zero");
        assert_eq!(u32::from_le_bytes(req[21..25].try_into().unwrap()), REQ_PQ_MULTI);
        let msg_id = u64::from_le_bytes(req[9..17].try_into().unwrap());
        assert_eq!(msg_id % 4, 0, "client message ids are divisible by 4");
        let nonce: [u8; 16] = req[25..41].try_into().unwrap();

        let mut body = vec![0u8; 8];
        body.extend_from_slice(&(msg_id | 1).to_le_bytes());
        let mut data = RES_PQ.to_vec();
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&[7u8; 16]); // server_nonce
        data.extend_from_slice(&[8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0]); // pq
        data.extend_from_slice(&[0x15, 0xc4, 0xb5, 0x1c, 1, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9]); // fingerprints
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&data);
        if tamper_nonce {
            body[20 + 4] ^= 0xFF;
        }
        let mut packet = vec![(body.len() / 4) as u8];
        packet.extend_from_slice(&body);
        srv_enc.apply_keystream(&mut packet);
        packet
    }

    #[test]
    fn valid_respq_is_accepted_even_when_split() {
        let mut p = Probe::new(2);
        let reply = server_reply(&p, false);
        assert_eq!(p.feed(&reply), Ok(true));

        let mut p = Probe::new(4);
        let reply = server_reply(&p, false);
        let (a, b) = reply.split_at(reply.len() / 2);
        assert_eq!(p.feed(a), Ok(false));
        assert_eq!(p.feed(b), Ok(true));
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let mut p = Probe::new(2);
        let reply = server_reply(&p, true);
        assert!(p.feed(&reply).unwrap_err().contains("nonce"));
    }

    #[test]
    fn transport_error_is_reported() {
        let mut p = Probe::new(2);
        let (_, mut srv_enc) = upstream_ciphers(&p.init);
        let mut pkt = vec![1u8];
        pkt.extend_from_slice(&(-404i32).to_le_bytes());
        srv_enc.apply_keystream(&mut pkt);
        let e = p.feed(&pkt).unwrap_err();
        assert!(e.contains("-404"), "{e}");
    }

    #[test]
    fn garbage_is_not_a_respq() {
        let mut p = Probe::new(2);
        let (_, mut srv_enc) = upstream_ciphers(&p.init);
        let mut pkt = vec![12u8];
        pkt.extend_from_slice(&[0xAB; 48]);
        srv_enc.apply_keystream(&mut pkt);
        assert!(p.feed(&pkt).unwrap_err().contains("not resPQ"));
    }

    #[test]
    fn probes_are_unique() {
        let (a, b) = (Probe::new(2), Probe::new(2));
        assert_ne!(a.init, b.init);
        assert_ne!(a.request, b.request);
    }
}
