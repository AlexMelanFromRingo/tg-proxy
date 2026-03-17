use std::net::Ipv4Addr;

/// Telegram IP ranges (used to detect Telegram traffic)
const TG_RANGES: &[(u32, u32)] = &[
    // 185.76.151.0/24
    (ip_to_u32([185, 76, 151, 0]), ip_to_u32([185, 76, 151, 255])),
    // 149.154.160.0/20
    (ip_to_u32([149, 154, 160, 0]), ip_to_u32([149, 154, 175, 255])),
    // 91.105.192.0/23
    (ip_to_u32([91, 105, 192, 0]), ip_to_u32([91, 105, 193, 255])),
    // 91.108.0.0/16
    (ip_to_u32([91, 108, 0, 0]), ip_to_u32([91, 108, 255, 255])),
];

const fn ip_to_u32(o: [u8; 4]) -> u32 {
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

pub fn is_telegram_ip(ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    TG_RANGES.iter().any(|&(lo, hi)| n >= lo && n <= hi)
}

/// Known Telegram DC server IPs mapped to (dc_id, is_media)
pub fn dc_from_ip(ip: Ipv4Addr) -> Option<(u8, bool)> {
    let s = ip.to_string();
    Some(match s.as_str() {
        // DC1
        "149.154.175.50" | "149.154.175.51" | "149.154.175.53" | "149.154.175.54" => (1, false),
        "149.154.175.52" => (1, true),
        // DC2
        "149.154.167.41" | "149.154.167.50" | "149.154.167.51"
        | "149.154.167.220" | "95.161.76.100" => (2, false),
        "149.154.167.151" | "149.154.167.222" | "149.154.167.223" | "149.154.162.123" => {
            (2, true)
        }
        // DC3
        "149.154.175.100" | "149.154.175.101" => (3, false),
        "149.154.175.102" => (3, true),
        // DC4
        "149.154.167.91" | "149.154.167.92" => (4, false),
        "149.154.164.250" | "149.154.166.120" | "149.154.166.121" | "149.154.167.118"
        | "149.154.165.111" => (4, true),
        // DC5
        "91.108.56.100" | "91.108.56.101" | "91.108.56.116" | "91.108.56.126"
        | "149.154.171.5" => (5, false),
        "91.108.56.102" | "91.108.56.128" | "91.108.56.151" => (5, true),
        _ => return None,
    })
}

/// Return WebSocket domain candidates for a given DC, ordered by preference.
/// Media DCs prefer the `-1` variant first.
pub fn ws_domains(dc: u8, is_media: bool) -> [String; 2] {
    if is_media {
        [
            format!("kws{}-1.web.telegram.org", dc),
            format!("kws{}.web.telegram.org", dc),
        ]
    } else {
        [
            format!("kws{}.web.telegram.org", dc),
            format!("kws{}-1.web.telegram.org", dc),
        ]
    }
}
