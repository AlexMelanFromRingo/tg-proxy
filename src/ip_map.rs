use std::net::Ipv4Addr;

/// Telegram IP ranges (used by the SOCKS5 front-end to decide what to intercept).
///
/// A superset of <https://core.telegram.org/resources/cidr.txt>: the whole
/// `91.108.0.0/16` and the legacy `95.161.64.0/20` are included because older
/// clients still talk to DCs there.
const TG_RANGES: &[(u32, u32)] = &[
    // 185.76.151.0/24
    (ip_to_u32([185, 76, 151, 0]), ip_to_u32([185, 76, 151, 255])),
    // 149.154.160.0/20
    (ip_to_u32([149, 154, 160, 0]), ip_to_u32([149, 154, 175, 255])),
    // 91.105.192.0/23
    (ip_to_u32([91, 105, 192, 0]), ip_to_u32([91, 105, 193, 255])),
    // 91.108.0.0/16
    (ip_to_u32([91, 108, 0, 0]), ip_to_u32([91, 108, 255, 255])),
    // 95.161.64.0/20
    (ip_to_u32([95, 161, 64, 0]), ip_to_u32([95, 161, 79, 255])),
];

const fn ip_to_u32(o: [u8; 4]) -> u32 {
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

pub fn is_telegram_ip(ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    TG_RANGES.iter().any(|&(lo, hi)| n >= lo && n <= hi)
}

/// Production DC TCP endpoints (MTProto over TCP/443). Used as the destination
/// for raw-TCP fallback and for the Cloudflare Worker (`dst=`).
pub const DC_DEFAULT_IPS: &[(u16, Ipv4Addr)] = &[
    (1, Ipv4Addr::new(149, 154, 175, 50)),
    (2, Ipv4Addr::new(149, 154, 167, 51)),
    (3, Ipv4Addr::new(149, 154, 175, 100)),
    (4, Ipv4Addr::new(149, 154, 167, 91)),
    (5, Ipv4Addr::new(149, 154, 171, 5)),
    (203, Ipv4Addr::new(91, 105, 192, 100)),
];

/// Telegram *test* environment DC endpoints.
pub const DC_TEST_IPS: &[(u16, Ipv4Addr)] = &[
    (1, Ipv4Addr::new(149, 154, 175, 10)),
    (2, Ipv4Addr::new(149, 154, 167, 40)),
    (3, Ipv4Addr::new(149, 154, 175, 117)),
];

pub fn dc_default_ip(dc: u16, is_test: bool) -> Option<Ipv4Addr> {
    let table = if is_test { DC_TEST_IPS } else { DC_DEFAULT_IPS };
    table.iter().find(|(d, _)| *d == dc).map(|(_, ip)| *ip)
}

/// DC ids the proxy knows how to talk about by number.
pub fn is_known_dc(dc: u16) -> bool {
    (1..=5).contains(&dc) || dc == 203
}

/// Known Telegram DC server IPs mapped to (dc_id, is_media)
pub fn dc_from_ip(ip: Ipv4Addr) -> Option<(u16, bool)> {
    let s = ip.to_string();
    Some(match s.as_str() {
        // DC1
        "149.154.175.50" | "149.154.175.51" | "149.154.175.53" | "149.154.175.54" => (1, false),
        "149.154.175.52" => (1, true),
        // DC2
        "149.154.167.41" | "149.154.167.50" | "149.154.167.51" | "149.154.167.220" | "95.161.76.100" => (2, false),
        "149.154.167.151" | "149.154.167.222" | "149.154.167.223" | "149.154.162.123" => (2, true),
        // DC3
        "149.154.175.100" | "149.154.175.101" => (3, false),
        "149.154.175.102" => (3, true),
        // DC4
        "149.154.167.91" | "149.154.167.92" => (4, false),
        "149.154.164.250" | "149.154.166.120" | "149.154.166.121" | "149.154.167.118" | "149.154.165.111" => (4, true),
        // DC5
        "91.108.56.100" | "91.108.56.101" | "91.108.56.116" | "91.108.56.126" | "149.154.171.5" => (5, false),
        "91.108.56.102" | "91.108.56.128" | "91.108.56.151" => (5, true),
        // DC203
        "91.105.192.100" => (203, false),
        _ => return None,
    })
}

/// WebSocket host candidates for a DC, ordered by preference.
/// Media connections prefer the `-1` variant. DC203 is served by the DC2 hosts.
pub fn ws_domains(dc: u16, is_media: bool) -> [String; 2] {
    let dc = if dc == 203 { 2 } else { dc };
    if is_media {
        [format!("kws{}-1.web.telegram.org", dc), format!("kws{}.web.telegram.org", dc)]
    } else {
        [format!("kws{}.web.telegram.org", dc), format!("kws{}-1.web.telegram.org", dc)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_ranges() {
        assert!(is_telegram_ip(Ipv4Addr::new(149, 154, 167, 220)));
        assert!(is_telegram_ip(Ipv4Addr::new(91, 105, 192, 100)));
        assert!(is_telegram_ip(Ipv4Addr::new(95, 161, 76, 100)));
        assert!(!is_telegram_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_telegram_ip(Ipv4Addr::new(149, 154, 159, 255)));
    }

    #[test]
    fn dc_tables() {
        assert_eq!(dc_from_ip(Ipv4Addr::new(149, 154, 167, 220)), Some((2, false)));
        assert_eq!(dc_from_ip(Ipv4Addr::new(91, 105, 192, 100)), Some((203, false)));
        assert_eq!(dc_default_ip(2, false), Some(Ipv4Addr::new(149, 154, 167, 51)));
        assert_eq!(dc_default_ip(2, true), Some(Ipv4Addr::new(149, 154, 167, 40)));
        assert_eq!(dc_default_ip(5, true), None);
        assert!(is_known_dc(203) && !is_known_dc(6));
    }

    #[test]
    fn ws_domain_order() {
        assert_eq!(ws_domains(2, false)[0], "kws2.web.telegram.org");
        assert_eq!(ws_domains(2, true)[0], "kws2-1.web.telegram.org");
        assert_eq!(ws_domains(203, false)[0], "kws2.web.telegram.org");
    }
}
