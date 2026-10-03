//! Optional upstream SOCKS5 proxy (`--upstream-socks5`).
//!
//! Lets every outbound connection of this program ride through a tunnel that
//! already exists on the machine (Xray, sing-box, a Shadowsocks client, Tor, …)
//! instead of reimplementing those protocols here. Domain names are resolved by
//! the proxy, not locally, which also sidesteps DNS tampering.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::websocket::Target;

#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamSocks {
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

// Never print credentials, not even by accident through `{:?}`.
impl std::fmt::Debug for UpstreamSocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamSocks")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth", &self.auth.as_ref().map(|_| "<set>"))
            .finish()
    }
}

impl std::fmt::Display for UpstreamSocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth = if self.auth.is_some() { " (with authentication)" } else { "" };
        if self.host.contains(':') {
            write!(f, "[{}]:{}{}", self.host, self.port, auth)
        } else {
            write!(f, "{}:{}{}", self.host, self.port, auth)
        }
    }
}

impl FromStr for UpstreamSocks {
    type Err = String;

    /// `[socks5://][user:pass@]host[:port]`, IPv6 hosts in brackets. Port defaults to 1080.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let s = s.strip_prefix("socks5h://").or_else(|| s.strip_prefix("socks5://")).unwrap_or(s);
        let s = s.trim_end_matches('/');
        if s.is_empty() {
            return Err("empty address".into());
        }
        let (auth, hostport) = match s.rsplit_once('@') {
            Some((userinfo, hp)) => {
                let (u, p) = userinfo.split_once(':').ok_or("credentials must be user:password")?;
                if u.len() > 255 || p.len() > 255 {
                    return Err("user and password must each be at most 255 bytes".into());
                }
                (Some((u.to_string(), p.to_string())), hp)
            }
            None => (None, s),
        };
        let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
            let (h, tail) = rest.split_once(']').ok_or("missing ']' in IPv6 address")?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| format!("invalid port {p:?}"))?,
                None if tail.is_empty() => 1080,
                None => return Err(format!("unexpected text after address: {tail:?}")),
            };
            (h.to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| format!("invalid port {p:?}"))?),
                None => (hostport.to_string(), 1080),
            }
        };
        if host.is_empty() {
            return Err("empty host".into());
        }
        if port == 0 {
            return Err("port must not be 0".into());
        }
        Ok(Self { host, port, auth })
    }
}

fn reply_error(code: u8) -> io::Error {
    let (kind, msg) = match code {
        0x01 => (io::ErrorKind::Other, "general SOCKS server failure"),
        0x02 => (io::ErrorKind::PermissionDenied, "connection not allowed by ruleset"),
        0x03 => (io::ErrorKind::Other, "network unreachable"),
        0x04 => (io::ErrorKind::Other, "host unreachable"),
        0x05 => (io::ErrorKind::ConnectionRefused, "connection refused"),
        0x06 => (io::ErrorKind::TimedOut, "TTL expired"),
        0x07 => (io::ErrorKind::Unsupported, "command not supported"),
        0x08 => (io::ErrorKind::Unsupported, "address type not supported"),
        _ => (io::ErrorKind::Other, "unknown SOCKS reply"),
    };
    io::Error::new(kind, format!("upstream SOCKS5: {msg}"))
}

fn proto_error(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("upstream SOCKS5: {msg}"))
}

fn encode_target(target: &Target, out: &mut Vec<u8>) -> io::Result<()> {
    let (addr, port): (Option<IpAddr>, u16);
    let mut name: Option<&str> = None;
    match target {
        Target::Addr(a) => {
            addr = Some(a.ip());
            port = a.port();
        }
        Target::Host(h, p) => {
            port = *p;
            match h.parse::<IpAddr>() {
                Ok(ip) => addr = Some(ip),
                Err(_) => {
                    addr = None;
                    name = Some(h);
                }
            }
        }
    }
    match (addr, name) {
        (Some(IpAddr::V4(ip)), _) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        (Some(IpAddr::V6(ip)), _) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
        (None, Some(n)) => {
            if n.is_empty() || n.len() > 255 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid host name length"));
            }
            out.push(0x03);
            out.push(n.len() as u8);
            out.extend_from_slice(n.as_bytes());
        }
        (None, None) => unreachable!(),
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// Open a TCP connection to `target` through `proxy` (SOCKS5 CONNECT).
pub async fn socks5_connect(proxy: &UpstreamSocks, target: &Target) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
    let _ = s.set_nodelay(true);

    // Greeting: offer "no auth", and user/password if we have credentials.
    let greeting: &[u8] = if proxy.auth.is_some() { &[5, 2, 0x00, 0x02] } else { &[5, 1, 0x00] };
    s.write_all(greeting).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != 5 {
        return Err(proto_error("not a SOCKS5 server"));
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            let Some((user, pass)) = &proxy.auth else {
                return Err(proto_error("server demands authentication"));
            };
            let mut msg = vec![1, user.len() as u8];
            msg.extend_from_slice(user.as_bytes());
            msg.push(pass.len() as u8);
            msg.extend_from_slice(pass.as_bytes());
            s.write_all(&msg).await?;
            let mut res = [0u8; 2];
            s.read_exact(&mut res).await?;
            if res[1] != 0 {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "upstream SOCKS5: authentication failed"));
            }
        }
        0xFF => return Err(proto_error("no acceptable authentication method")),
        _ => return Err(proto_error("unsupported authentication method")),
    }

    // CONNECT request.
    let mut req = vec![5, 1, 0];
    encode_target(target, &mut req)?;
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(proto_error("bad reply version"));
    }
    if head[1] != 0 {
        return Err(reply_error(head[1]));
    }
    // Skip the bound address.
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => return Err(proto_error("bad address type in reply")),
    };
    let mut sink = vec![0u8; skip];
    s.read_exact(&mut sink).await?;
    Ok(s)
}

/// Resolve nothing here: callers hand over a [`Target`] and get a connected socket.
pub async fn connect(target: &Target, upstream: Option<&UpstreamSocks>) -> io::Result<TcpStream> {
    match upstream {
        Some(up) => socks5_connect(up, target).await,
        None => crate::websocket::tcp_connect_direct(target).await,
    }
}

pub fn target_for(addr: SocketAddr) -> Target {
    Target::Addr(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parsing() {
        let p: UpstreamSocks = "127.0.0.1:10808".parse().unwrap();
        assert_eq!((p.host.as_str(), p.port, p.auth.clone()), ("127.0.0.1", 10808, None));

        let p: UpstreamSocks = "socks5://user:p@ss:word@proxy.example:1081/".parse().unwrap();
        assert_eq!(p.host, "proxy.example");
        assert_eq!(p.port, 1081);
        assert_eq!(p.auth, Some(("user".into(), "p@ss:word".into())));

        let p: UpstreamSocks = "[::1]:9050".parse().unwrap();
        assert_eq!((p.host.as_str(), p.port), ("::1", 9050));
        assert_eq!("[::1]".parse::<UpstreamSocks>().unwrap().port, 1080);
        assert_eq!("localhost".parse::<UpstreamSocks>().unwrap().port, 1080);

        for bad in ["", "host:0", "host:99999", "host:abc", "u@host:1", "[::1", ":1080", "[::1]x"] {
            assert!(bad.parse::<UpstreamSocks>().is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn debug_hides_credentials() {
        let p: UpstreamSocks = "bob:hunter2@h:1".parse().unwrap();
        let shown = format!("{p:?} {p}");
        assert!(!shown.contains("hunter2") && !shown.contains("bob"));
    }

    /// Minimal SOCKS5 server for tests: returns the requested target on a channel.
    async fn mock_socks(
        require_auth: Option<(&'static str, &'static str)>,
        reply: u8,
    ) -> (SocketAddr, tokio::sync::mpsc::Receiver<(String, u16)>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut h = [0u8; 2];
            s.read_exact(&mut h).await.unwrap();
            let mut methods = vec![0u8; h[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            match require_auth {
                Some((u, p)) => {
                    assert!(methods.contains(&0x02));
                    s.write_all(&[5, 2]).await.unwrap();
                    let mut v = [0u8; 2];
                    s.read_exact(&mut v).await.unwrap();
                    let mut user = vec![0u8; v[1] as usize];
                    s.read_exact(&mut user).await.unwrap();
                    let mut pl = [0u8; 1];
                    s.read_exact(&mut pl).await.unwrap();
                    let mut pass = vec![0u8; pl[0] as usize];
                    s.read_exact(&mut pass).await.unwrap();
                    let ok = user == u.as_bytes() && pass == p.as_bytes();
                    s.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                    if !ok {
                        return;
                    }
                }
                None => s.write_all(&[5, 0]).await.unwrap(),
            }
            let mut r = [0u8; 4];
            s.read_exact(&mut r).await.unwrap();
            assert_eq!(&r[..3], &[5, 1, 0]);
            let host = match r[3] {
                1 => {
                    let mut a = [0u8; 4];
                    s.read_exact(&mut a).await.unwrap();
                    std::net::Ipv4Addr::from(a).to_string()
                }
                4 => {
                    let mut a = [0u8; 16];
                    s.read_exact(&mut a).await.unwrap();
                    std::net::Ipv6Addr::from(a).to_string()
                }
                3 => {
                    let mut l = [0u8; 1];
                    s.read_exact(&mut l).await.unwrap();
                    let mut n = vec![0u8; l[0] as usize];
                    s.read_exact(&mut n).await.unwrap();
                    String::from_utf8(n).unwrap()
                }
                _ => panic!("bad atyp"),
            };
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.unwrap();
            tx.send((host, u16::from_be_bytes(p))).await.unwrap();
            // Reply with a domain-type bound address to exercise the skip logic.
            let mut resp = vec![5, reply, 0, 3, 4];
            resp.extend_from_slice(b"bind");
            resp.extend_from_slice(&[0, 0]);
            s.write_all(&resp).await.unwrap();
            if reply == 0 {
                let mut buf = [0u8; 16];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(&buf[..n]).await.unwrap(); // echo
            }
        });
        (addr, rx)
    }

    fn proxy(addr: SocketAddr, auth: Option<(&str, &str)>) -> UpstreamSocks {
        UpstreamSocks { host: addr.ip().to_string(), port: addr.port(), auth: auth.map(|(u, p)| (u.into(), p.into())) }
    }

    #[tokio::test]
    async fn connects_by_ipv4_and_carries_data() {
        let (addr, mut rx) = mock_socks(None, 0).await;
        let target = Target::Addr("149.154.167.51:443".parse().unwrap());
        let mut s = socks5_connect(&proxy(addr, None), &target).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), ("149.154.167.51".to_string(), 443));
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
    }

    #[tokio::test]
    async fn domain_names_are_sent_to_the_proxy_unresolved() {
        let (addr, mut rx) = mock_socks(None, 0).await;
        let target = Target::Host("w.example.workers.dev".into(), 443);
        socks5_connect(&proxy(addr, None), &target).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), ("w.example.workers.dev".to_string(), 443));
    }

    #[tokio::test]
    async fn ip_literal_hosts_use_address_types() {
        let (addr, mut rx) = mock_socks(None, 0).await;
        socks5_connect(&proxy(addr, None), &Target::Host("::1".into(), 80)).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), ("::1".to_string(), 80));
    }

    #[tokio::test]
    async fn username_password_auth() {
        let (addr, mut rx) = mock_socks(Some(("bob", "secret")), 0).await;
        let t = Target::Addr("1.2.3.4:5".parse().unwrap());
        socks5_connect(&proxy(addr, Some(("bob", "secret"))), &t).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().1, 5);

        let (addr, _rx) = mock_socks(Some(("bob", "secret")), 0).await;
        let e = socks5_connect(&proxy(addr, Some(("bob", "wrong"))), &t).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn refusal_codes_map_to_errors() {
        let (addr, _rx) = mock_socks(None, 5).await;
        let t = Target::Addr("1.2.3.4:5".parse().unwrap());
        let e = socks5_connect(&proxy(addr, None), &t).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn rejects_non_socks_peers() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 8];
            let _ = s.read(&mut b).await;
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n").await;
        });
        let t = Target::Addr("1.2.3.4:5".parse().unwrap());
        let e = socks5_connect(&proxy(addr, None), &t).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }
}
