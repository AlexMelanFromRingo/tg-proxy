use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use rand::RngCore;

/// SNI used by the "fronting" connection mode: a connection to Telegram's WS
/// gateway that presents an innocuous, locally-whitelisted server name while the
/// HTTP `Host` still selects the real `kws*.web.telegram.org` backend.
pub const DEFAULT_FRONTING_SNI: &str = "sprinthost.ru";

/// Runtime settings shared by every component.
#[derive(Debug, Clone)]
pub struct Settings {
    pub host: String,
    /// SOCKS5 listener port; 0 disables it.
    pub socks_port: u16,
    /// MTProto-proxy listener port; 0 disables it.
    pub mtproto_port: u16,
    pub secret: [u8; 16],
    /// DC id -> IP of Telegram's WebSocket gateway (direct WS routes).
    pub dc_redirects: HashMap<u16, Ipv4Addr>,
    pub buffer_size: usize,
    pub pool_size: usize,
    pub pool_max_age: Duration,
    pub connect_timeout: Duration,
    pub skip_tls_verify: bool,
    /// Empty string disables fronting.
    pub fronting_sni: String,
    pub fallback_cfproxy: bool,
    pub cfproxy_user_domains: Vec<String>,
    pub cfproxy_worker_domains: Vec<String>,
    /// Talk to CF-proxy / CF-worker over plain port 80 instead of TLS.
    pub disable_secure: bool,
    pub fake_tls_domain: String,
    pub proxy_protocol: bool,
    pub force_test_dc: bool,
    /// Port of Telegram's WS gateway (443; overridable only so tests can point
    /// the direct route at a local mock).
    pub gateway_port: u16,
    /// Port of the fake-TLS masking website (443; overridable for tests).
    pub masking_port: u16,
    /// Route every outbound connection through this SOCKS5 proxy.
    pub upstream_socks5: Option<std::sync::Arc<crate::upstream::UpstreamSocks>>,
}

impl Default for Settings {
    fn default() -> Self {
        let mut secret = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self {
            host: "127.0.0.1".into(),
            socks_port: 1080,
            mtproto_port: 1443,
            secret,
            dc_redirects: default_dc_redirects(),
            buffer_size: 256 * 1024,
            pool_size: 4,
            pool_max_age: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(5),
            skip_tls_verify: false,
            fronting_sni: DEFAULT_FRONTING_SNI.into(),
            fallback_cfproxy: true,
            cfproxy_user_domains: Vec::new(),
            cfproxy_worker_domains: Vec::new(),
            disable_secure: false,
            fake_tls_domain: String::new(),
            proxy_protocol: false,
            force_test_dc: false,
            gateway_port: 443,
            masking_port: 443,
            upstream_socks5: None,
        }
    }
}

impl Settings {
    pub fn dc_ip(&self, dc: u16) -> Option<Ipv4Addr> {
        self.dc_redirects.get(&dc).copied()
    }

    pub fn any_cf_fallback(&self) -> bool {
        self.fallback_cfproxy || !self.cfproxy_worker_domains.is_empty()
    }

    pub fn secret_hex(&self) -> String {
        hex(&self.secret)
    }
}

/// The only IP that currently serves Telegram's WS gateway for DC2/DC4.
pub fn default_dc_redirects() -> HashMap<u16, Ipv4Addr> {
    let ip = Ipv4Addr::new(149, 154, 167, 220);
    HashMap::from([(2, ip), (4, ip)])
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Parse `DC:IP` entries (`--dc-ip 2:149.154.167.220`).
pub fn parse_dc_ips(entries: &[String]) -> anyhow::Result<HashMap<u16, Ipv4Addr>> {
    let mut map = HashMap::new();
    for entry in entries {
        let (dc_str, ip_str) = entry
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Invalid --dc-ip format {:?}, expected DC:IP", entry))?;
        let dc: u16 = dc_str.trim().parse().map_err(|_| anyhow::anyhow!("Invalid DC number: {:?}", dc_str))?;
        let ip: Ipv4Addr = ip_str.trim().parse().map_err(|_| anyhow::anyhow!("Invalid IP address: {:?}", ip_str))?;
        if !crate::ip_map::is_known_dc(dc) {
            anyhow::bail!("DC must be 1-5 or 203, got {}", dc);
        }
        map.insert(dc, ip);
    }
    Ok(map)
}

pub fn parse_secret(s: &str) -> anyhow::Result<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        anyhow::bail!("Secret must be exactly 32 hex characters");
    }
    let bytes = unhex(s).ok_or_else(|| anyhow::anyhow!("Secret must be valid hex"))?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ── Domain lists ──────────────────────────────────────────────────────────────

/// Accept comma / semicolon / whitespace separated values, strip URL schemes and
/// paths (people paste `https://x.workers.dev/`), dedupe case-insensitively.
pub fn coerce_domain_list(values: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for v in values {
        for item in v.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let item = item.trim();
            let item = item
                .strip_prefix("https://")
                .or_else(|| item.strip_prefix("http://"))
                .or_else(|| item.strip_prefix("wss://"))
                .or_else(|| item.strip_prefix("ws://"))
                .unwrap_or(item);
            let item = item.split('/').next().unwrap_or("").trim();
            if item.is_empty() {
                continue;
            }
            if seen.insert(item.to_ascii_lowercase()) {
                out.push(item.to_string());
            }
        }
    }
    out
}

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.chars().any(|c| c.is_ascii_alphabetic())
}

pub fn normalize_domain_pool(domains: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for d in domains {
        let item = d.trim().to_ascii_lowercase();
        if is_valid_domain(&item) && seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

/// Decoder for the community CF-proxy domain list. The list is distributed in a
/// lightly obfuscated form (a Caesar shift keyed by the label's letter count and
/// a swapped TLD) so it is not trivially greppable; this mirrors the upstream
/// project's `_dd` so both the built-in and the downloaded lists decode alike.
pub fn decode_cf_domain(s: &str) -> String {
    let Some(p) = s.strip_suffix(".com") else {
        return s.to_string();
    };
    let n = p.chars().filter(|c| c.is_ascii_alphabetic()).count() as i32;
    let shifted: String = p
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' } as i32;
                ((c as i32 - base - n).rem_euclid(26) + base) as u8 as char
            } else {
                c
            }
        })
        .collect();
    shifted + ".co.uk"
}

const CFPROXY_ENCODED: &[&str] = &[
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
];

pub fn default_cfproxy_domains() -> Vec<String> {
    CFPROXY_ENCODED.iter().map(|d| decode_cf_domain(d)).collect()
}

/// Minimum number of valid domains in a downloaded list for it to be accepted.
pub const CFPROXY_MIN_VALID_DOMAINS: usize = 3;

pub const CFPROXY_DOMAINS_URL_HOST: &str = "raw.githubusercontent.com";
pub const CFPROXY_DOMAINS_URL_PATH: &str = "/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";
/// GitHub's CDN address, tried before DNS (DNS for github hosts is often
/// tampered with on censored networks). Falls back to normal resolution.
pub const GITHUB_PINNED_IP: Ipv4Addr = Ipv4Addr::new(185, 199, 109, 133);

// ── Persistent secret ─────────────────────────────────────────────────────────

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

fn config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        home_dir().map(|h| h.join("Library").join("Application Support"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| home_dir().map(|h| h.join(".config")))
    }
}

pub fn secret_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("tg-proxy").join("secret"))
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecretSource {
    Cli,
    Loaded(PathBuf),
    Generated(PathBuf),
    /// Generated but could not be stored: it changes on every start.
    Ephemeral,
}

/// Load the persisted secret, or create and store a new one. Keeping it stable
/// matters: a new secret on every start would force everyone to re-add the proxy.
pub fn load_or_create_secret() -> ([u8; 16], SecretSource) {
    load_or_create_secret_at(secret_path())
}

pub fn load_or_create_secret_at(path: Option<PathBuf>) -> ([u8; 16], SecretSource) {
    if let Some(path) = &path {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(secret) = parse_secret(&text) {
                return (secret, SecretSource::Loaded(path.clone()));
            }
        }
    }
    let mut secret = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    if let Some(path) = path {
        if store_secret(&path, &secret).is_ok() {
            return (secret, SecretSource::Generated(path));
        }
    }
    (secret, SecretSource::Ephemeral)
}

fn store_secret(path: &PathBuf, secret: &[u8; 16]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    writeln!(f, "{}", hex(secret))
}

/// Host to print in `tg://` links. For `0.0.0.0` this finds the LAN address the
/// OS would use for outbound traffic (no packet is sent).
pub fn link_host(host: &str) -> String {
    if host != "0.0.0.0" {
        return host.to_string();
    }
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc_ip_parsing() {
        let m = parse_dc_ips(&["2:149.154.167.220".into(), "203:1.2.3.4".into()]).unwrap();
        assert_eq!(m[&2], Ipv4Addr::new(149, 154, 167, 220));
        assert_eq!(m[&203], Ipv4Addr::new(1, 2, 3, 4));
        assert!(parse_dc_ips(&["6:1.2.3.4".into()]).is_err());
        assert!(parse_dc_ips(&["2:nope".into()]).is_err());
        assert!(parse_dc_ips(&["nocolon".into()]).is_err());
    }

    #[test]
    fn secret_parsing() {
        let s = parse_secret("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(hex(&s), "00112233445566778899aabbccddeeff");
        assert!(parse_secret("abcd").is_err());
        assert!(parse_secret("zz112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn domain_list_coercion() {
        let v = coerce_domain_list(&[
            "A.workers.dev, b.workers.dev;https://c.workers.dev/apiws".into(),
            "a.WORKERS.dev".into(),
        ]);
        assert_eq!(v, vec!["A.workers.dev", "b.workers.dev", "c.workers.dev"]);
    }

    #[test]
    fn domain_validation() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("a-b.c.example.co.uk"));
        assert!(!is_valid_domain("nodot"));
        assert!(!is_valid_domain("-bad.com"));
        assert!(!is_valid_domain("bad-.com"));
        assert!(!is_valid_domain("a..com"));
        assert!(!is_valid_domain("example.c"));
        assert!(!is_valid_domain("example.123"));
        assert!(!is_valid_domain("under_score.com"));
    }

    // Golden values computed with the upstream Python decoder.
    #[test]
    fn cf_domain_decoder_matches_upstream() {
        assert_eq!(decode_cf_domain("virkgj.com"), "pclead.co.uk");
        assert_eq!(decode_cf_domain("vmmzovy.com"), "offshor.co.uk");
        assert_eq!(decode_cf_domain("mkuosckvso.com"), "cakeisalie.co.uk");
        assert_eq!(decode_cf_domain("Ab-Cd.com"), "Wx-Yz.co.uk");
        assert_eq!(decode_cf_domain("plain.org"), "plain.org");
        let all = default_cfproxy_domains();
        assert_eq!(all.len(), 20);
        assert!(all.iter().all(|d| is_valid_domain(d)));
    }

    #[test]
    fn secret_roundtrip_on_disk() {
        let dir = std::env::temp_dir().join(format!("tgproxy-test-{}", std::process::id()));
        let path = dir.join("secret");
        let (a, src) = load_or_create_secret_at(Some(path.clone()));
        assert_eq!(src, SecretSource::Generated(path.clone()));
        let (b, src) = load_or_create_secret_at(Some(path.clone()));
        assert_eq!(src, SecretSource::Loaded(path));
        assert_eq!(a, b);
        let _ = std::fs::remove_dir_all(dir);
        let (_, src) = load_or_create_secret_at(None);
        assert_eq!(src, SecretSource::Ephemeral);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(unhex("00ff10").unwrap(), vec![0, 255, 16]);
        assert!(unhex("0").is_none());
        assert!(unhex("gg").is_none());
    }
}
