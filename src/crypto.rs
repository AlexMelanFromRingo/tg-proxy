//! MTProto "obfuscated2" transport primitives.
//!
//! Telegram clients wrap every TCP connection in an AES-256-CTR stream whose key
//! material is the first 64 bytes they send (the *init packet*). The tail of that
//! packet, once decrypted, carries a protocol tag and the datacenter index. When
//! the client talks to us through an MTProto proxy the keys are additionally mixed
//! with the proxy *secret*, so we decrypt with the client's keys and re-encrypt
//! with fresh keys towards Telegram (`UpCrypto` / `DownCrypto`).

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub type Aes256Ctr = Ctr128BE<Aes256>;

pub const HANDSHAKE_LEN: usize = 64;
const SKIP_LEN: usize = 8;
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;

pub const PROTO_ABRIDGED: u32 = 0xEFEF_EFEF;
pub const PROTO_INTERMEDIATE: u32 = 0xEEEE_EEEE;
pub const PROTO_PADDED: u32 = 0xDDDD_DDDD;

const MAX_PACKET: usize = 16 * 1024 * 1024;

fn cipher(key: &[u8], iv: &[u8]) -> Aes256Ctr {
    Aes256Ctr::new_from_slices(key, iv).expect("AES-256-CTR key/iv length")
}

fn advance_init(c: &mut Aes256Ctr) {
    let mut skip = [0u8; HANDSHAKE_LEN];
    c.apply_keystream(&mut skip);
}

fn is_proto_tag(tag: u32) -> bool {
    matches!(tag, PROTO_ABRIDGED | PROTO_INTERMEDIATE | PROTO_PADDED)
}

// ── Client init (what Telegram clients send) ──────────────────────────────────

/// What the proxy learns from a client's init packet.
#[derive(Debug, Clone)]
pub struct ClientHandshake {
    /// Raw signed DC index: negative means "media" connection.
    pub dc_raw: i16,
    pub proto: u32,
    /// `init[8..56]` — needed to derive both directions' keys.
    pub prekey_iv: [u8; 48],
}

/// Validate a client init packet against the proxy `secret`.
/// Returns `None` for a wrong secret or a non-MTProto stream.
pub fn try_handshake(init: &[u8; HANDSHAKE_LEN], secret: &[u8; 16]) -> Option<ClientHandshake> {
    let prekey_iv: [u8; 48] = init[SKIP_LEN..SKIP_LEN + 48].try_into().ok()?;
    let key = secret_key(&prekey_iv[..PREKEY_LEN], secret);
    let mut dec = *init;
    cipher(&key, &prekey_iv[PREKEY_LEN..]).apply_keystream(&mut dec);

    let proto = u32::from_le_bytes(dec[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().ok()?);
    if !is_proto_tag(proto) {
        return None;
    }
    let dc_raw = i16::from_le_bytes(dec[DC_IDX_POS..DC_IDX_POS + 2].try_into().ok()?);
    Some(ClientHandshake { dc_raw, proto, prekey_iv })
}

fn secret_key(prekey: &[u8], secret: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prekey);
    h.update(secret);
    h.finalize().into()
}

/// Split a raw signed DC index into `(dc, is_media, is_test)`.
/// Telegram Desktop marks test-environment DCs by adding 10000.
pub fn normalize_dc(dc_raw: i16, force_test: bool) -> (u16, bool, bool) {
    let media = dc_raw < 0;
    let mut dc = dc_raw.unsigned_abs();
    let mut test = force_test;
    if dc >= 10000 {
        test = true;
        dc -= 10000;
    }
    (dc, media, test)
}

// ── Relay init (what we send to Telegram) ─────────────────────────────────────

fn random_init_prefix() -> [u8; HANDSHAKE_LEN] {
    let mut rng = rand::thread_rng();
    loop {
        let mut rnd = [0u8; HANDSHAKE_LEN];
        rng.fill_bytes(&mut rnd);
        if rnd[0] == 0xEF {
            continue;
        }
        let first4 = &rnd[..4];
        if first4 == b"HEAD"
            || first4 == b"POST"
            || first4 == b"GET "
            || first4 == [0xEE; 4]
            || first4 == [0xDD; 4]
            || first4 == [0x16, 0x03, 0x01, 0x02]
        {
            continue;
        }
        if rnd[4..8] == [0, 0, 0, 0] {
            continue;
        }
        return rnd;
    }
}

/// Set the encrypted tail (proto tag + dc index + 2 random bytes) of `rnd`, given
/// the AES key/iv that will encrypt the init packet. Returns the final init and
/// the cipher already advanced past it.
fn finish_init(
    mut rnd: [u8; HANDSHAKE_LEN],
    key: &[u8],
    iv: &[u8],
    proto_tag: [u8; 4],
    dc_idx: i16,
) -> ([u8; HANDSHAKE_LEN], Aes256Ctr) {
    let mut c = cipher(key, iv);
    let mut enc_full = rnd;
    c.apply_keystream(&mut enc_full);

    let mut tail_plain = [0u8; 8];
    tail_plain[..4].copy_from_slice(&proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    rand::thread_rng().fill_bytes(&mut tail_plain[6..]);

    for i in 0..8 {
        let keystream = enc_full[PROTO_TAG_POS + i] ^ rnd[PROTO_TAG_POS + i];
        rnd[PROTO_TAG_POS + i] = tail_plain[i] ^ keystream;
    }
    (rnd, c)
}

/// Generate a plain (secret-less) obfuscated2 init for talking to Telegram.
pub fn generate_relay_init(proto: u32, dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    let rnd = random_init_prefix();
    let (init, _) = finish_init(
        rnd,
        &rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN],
        &rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN],
        proto.to_le_bytes(),
        dc_idx,
    );
    init
}

/// Ciphers for the Telegram side of a connection that was opened with `relay_init`:
/// `(encrypt towards Telegram — already past the init, decrypt from Telegram)`.
pub fn upstream_ciphers(relay_init: &[u8; HANDSHAKE_LEN]) -> (Aes256Ctr, Aes256Ctr) {
    let mut enc = cipher(
        &relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN],
        &relay_init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN],
    );
    advance_init(&mut enc);

    let mut rev: Vec<u8> = relay_init[SKIP_LEN..SKIP_LEN + 48].to_vec();
    rev.reverse();
    let dec = cipher(&rev[..PREKEY_LEN], &rev[PREKEY_LEN..]);
    (enc, dec)
}

// ── Re-encryption contexts ────────────────────────────────────────────────────

/// client → Telegram: decrypt with the client's key, encrypt with the relay key.
pub struct UpCrypto {
    clt_dec: Aes256Ctr,
    tg_enc: Aes256Ctr,
}

/// Telegram → client: decrypt with the relay key, encrypt with the client's key.
pub struct DownCrypto {
    tg_dec: Aes256Ctr,
    clt_enc: Aes256Ctr,
}

impl UpCrypto {
    /// Step 1: turn client ciphertext into plaintext (in place).
    pub fn decrypt_client(&mut self, buf: &mut [u8]) {
        self.clt_dec.apply_keystream(buf);
    }
    /// Step 2: turn plaintext into ciphertext for Telegram (in place).
    pub fn encrypt_upstream(&mut self, buf: &mut [u8]) {
        self.tg_enc.apply_keystream(buf);
    }
}

impl DownCrypto {
    pub fn reencrypt(&mut self, buf: &mut [u8]) {
        self.tg_dec.apply_keystream(buf);
        self.clt_enc.apply_keystream(buf);
    }
}

pub fn build_crypto(
    hs: &ClientHandshake,
    secret: &[u8; 16],
    relay_init: &[u8; HANDSHAKE_LEN],
) -> (UpCrypto, DownCrypto) {
    let dec_key = secret_key(&hs.prekey_iv[..PREKEY_LEN], secret);
    let mut clt_dec = cipher(&dec_key, &hs.prekey_iv[PREKEY_LEN..]);
    advance_init(&mut clt_dec);

    let mut rev = hs.prekey_iv;
    rev.reverse();
    let enc_key = secret_key(&rev[..PREKEY_LEN], secret);
    let clt_enc = cipher(&enc_key, &rev[PREKEY_LEN..]);

    let (tg_enc, tg_dec) = upstream_ciphers(relay_init);
    (UpCrypto { clt_dec, tg_enc }, DownCrypto { tg_dec, clt_enc })
}

// ── SOCKS5 mode: transparent (secret-less) init ───────────────────────────────

/// Inspect a client's *plain* obfuscated2 init (SOCKS5 mode: the client talks to
/// the real DC protocol, no proxy secret involved).
pub fn peek_client_init(init: &[u8]) -> Option<ClientHandshake> {
    if init.len() < HANDSHAKE_LEN {
        return None;
    }
    let prekey_iv: [u8; 48] = init[SKIP_LEN..SKIP_LEN + 48].try_into().ok()?;
    let mut dec: [u8; HANDSHAKE_LEN] = init[..HANDSHAKE_LEN].try_into().ok()?;
    cipher(&prekey_iv[..PREKEY_LEN], &prekey_iv[PREKEY_LEN..]).apply_keystream(&mut dec);
    let proto = u32::from_le_bytes(dec[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().ok()?);
    if !is_proto_tag(proto) {
        return None;
    }
    let dc_raw = i16::from_le_bytes(dec[DC_IDX_POS..DC_IDX_POS + 2].try_into().ok()?);
    Some(ClientHandshake { dc_raw, proto, prekey_iv })
}

/// Rewrite the DC index inside a plain obfuscated2 init (keeps the keys intact).
/// `is_media` → negative index.
pub fn patch_dc(init: &mut [u8], dc: u16, is_media: bool) {
    if init.len() < HANDSHAKE_LEN || dc == 0 || dc > i16::MAX as u16 {
        return;
    }
    let dc_signed = if is_media { -(dc as i16) } else { dc as i16 };
    let new_dc = dc_signed.to_le_bytes();
    let mut keystream = [0u8; HANDSHAKE_LEN];
    cipher(&init[SKIP_LEN..SKIP_LEN + PREKEY_LEN], &init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + 48])
        .apply_keystream(&mut keystream);
    init[DC_IDX_POS] = keystream[DC_IDX_POS] ^ new_dc[0];
    init[DC_IDX_POS + 1] = keystream[DC_IDX_POS + 1] ^ new_dc[1];
}

/// A decryptor for the client→server stream of a plain obfuscated2 connection,
/// positioned right after the init packet. Used only to find message boundaries.
pub fn stream_decryptor(init: &[u8]) -> Option<Aes256Ctr> {
    if init.len() < HANDSHAKE_LEN {
        return None;
    }
    let mut c = cipher(&init[SKIP_LEN..SKIP_LEN + PREKEY_LEN], &init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + 48]);
    advance_init(&mut c);
    Some(c)
}

// ── Message splitter ──────────────────────────────────────────────────────────

/// Splits a client→Telegram byte stream into individual MTProto transport
/// packets so each can travel as its own WebSocket frame (the WS gateway expects
/// one packet per frame, while TCP reads can coalesce or cut packets anywhere).
///
/// It is fed both the plaintext (to read length prefixes) and the matching
/// ciphertext (what actually gets sent).
pub struct MsgSplitter {
    proto: u32,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

enum PacketLen {
    NeedMore,
    Invalid,
    Len(usize),
}

impl MsgSplitter {
    pub fn new(proto: u32) -> Self {
        Self { proto, cipher_buf: Vec::new(), plain_buf: Vec::new(), disabled: false }
    }

    pub fn split(&mut self, plain: &[u8], cipher: &[u8]) -> Vec<Vec<u8>> {
        debug_assert_eq!(plain.len(), cipher.len());
        if cipher.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![cipher.to_vec()];
        }
        self.plain_buf.extend_from_slice(plain);
        self.cipher_buf.extend_from_slice(cipher);

        let total = self.cipher_buf.len();
        let mut parts = Vec::new();
        let mut offset = 0;
        while offset < total {
            match self.next_len(offset, total - offset) {
                PacketLen::NeedMore => break,
                PacketLen::Invalid => {
                    parts.push(self.cipher_buf[offset..].to_vec());
                    offset = total;
                    self.disabled = true;
                    break;
                }
                PacketLen::Len(n) => {
                    parts.push(self.cipher_buf[offset..offset + n].to_vec());
                    offset += n;
                }
            }
        }
        if offset > 0 {
            self.cipher_buf.drain(..offset);
            self.plain_buf.drain(..offset);
        }
        parts
    }

    /// Whatever is still buffered (an incomplete trailing packet).
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            return None;
        }
        self.plain_buf.clear();
        Some(std::mem::take(&mut self.cipher_buf))
    }

    fn next_len(&self, offset: usize, avail: usize) -> PacketLen {
        let p = &self.plain_buf;
        let (header, payload) = match self.proto {
            PROTO_ABRIDGED => {
                let first = p[offset];
                if first == 0x7F || first == 0xFF {
                    if avail < 4 {
                        return PacketLen::NeedMore;
                    }
                    let n = u32::from_le_bytes([p[offset + 1], p[offset + 2], p[offset + 3], 0]);
                    (4, n as usize * 4)
                } else {
                    (1, (first & 0x7F) as usize * 4)
                }
            }
            PROTO_INTERMEDIATE | PROTO_PADDED => {
                if avail < 4 {
                    return PacketLen::NeedMore;
                }
                let n = u32::from_le_bytes([p[offset], p[offset + 1], p[offset + 2], p[offset + 3]]) & 0x7FFF_FFFF;
                (4, n as usize)
            }
            _ => return PacketLen::Invalid,
        };
        if payload == 0 || payload > MAX_PACKET {
            return PacketLen::Invalid;
        }
        let total = header + payload;
        if avail < total {
            PacketLen::NeedMore
        } else {
            PacketLen::Len(total)
        }
    }
}

// ── Client simulation (tests and `--check`) ───────────────────────────────────

/// Build the init a Telegram client would send through an MTProto proxy with
/// `secret`, together with the client's `(encrypt, decrypt)` ciphers.
pub fn client_init_with_secret(
    secret: &[u8; 16],
    proto: u32,
    dc_idx: i16,
) -> ([u8; HANDSHAKE_LEN], Aes256Ctr, Aes256Ctr) {
    let rnd = random_init_prefix();
    let enc_key = secret_key(&rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN], secret);
    let (init, enc) =
        finish_init(rnd, &enc_key, &rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + 48], proto.to_le_bytes(), dc_idx);
    let mut rev: Vec<u8> = rnd[SKIP_LEN..SKIP_LEN + 48].to_vec();
    rev.reverse();
    let dec_key = secret_key(&rev[..PREKEY_LEN], secret);
    let dec = cipher(&dec_key, &rev[PREKEY_LEN..]);
    (init, enc, dec)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = [7u8; 16];

    #[test]
    fn relay_init_is_valid_and_peekable() {
        for dc in [1i16, 2, -2, 4, -4, 5, 203, -203] {
            for proto in [PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED] {
                let init = generate_relay_init(proto, dc);
                assert_ne!(init[0], 0xEF);
                assert_ne!(&init[..4], b"POST");
                assert_ne!(&init[4..8], &[0, 0, 0, 0]);
                let hs = peek_client_init(&init).expect("peekable");
                assert_eq!(hs.dc_raw, dc);
                assert_eq!(hs.proto, proto);
            }
        }
    }

    #[test]
    fn handshake_roundtrip_and_wrong_secret() {
        let (init, _, _) = client_init_with_secret(&SECRET, PROTO_PADDED, -4);
        let hs = try_handshake(&init, &SECRET).expect("valid handshake");
        assert_eq!(hs.dc_raw, -4);
        assert_eq!(hs.proto, PROTO_PADDED);
        assert!(try_handshake(&init, &[9u8; 16]).is_none());
        // A secret-less init is not valid for a proxy with a secret.
        let plain = generate_relay_init(PROTO_ABRIDGED, 2);
        assert!(try_handshake(&plain, &SECRET).is_none());
    }

    #[test]
    fn dc_normalization() {
        assert_eq!(normalize_dc(2, false), (2, false, false));
        assert_eq!(normalize_dc(-4, false), (4, true, false));
        assert_eq!(normalize_dc(10002, false), (2, false, true));
        assert_eq!(normalize_dc(-10001, false), (1, true, true));
        assert_eq!(normalize_dc(203, true), (203, false, true));
    }

    #[test]
    fn full_reencryption_both_directions() {
        let (init, mut c_enc, mut c_dec) = client_init_with_secret(&SECRET, PROTO_ABRIDGED, 2);
        let hs = try_handshake(&init, &SECRET).unwrap();
        let relay_init = generate_relay_init(hs.proto, hs.dc_raw);
        let (mut up, mut down) = build_crypto(&hs, &SECRET, &relay_init);

        // The "Telegram" side derives its keys from the relay init alone.
        let (_, mut tg_dec_of_proxy_output) = {
            // decrypts what the proxy sends upstream
            let mut c = cipher(&relay_init[8..40], &relay_init[40..56]);
            advance_init(&mut c);
            (0, c)
        };
        let mut tg_enc_towards_proxy = {
            let mut rev: Vec<u8> = relay_init[8..56].to_vec();
            rev.reverse();
            cipher(&rev[..32], &rev[32..])
        };

        // client → telegram
        let msg = b"hello telegram, this is an MTProto payload!!".to_vec();
        let mut wire = msg.clone();
        c_enc.apply_keystream(&mut wire);
        assert_ne!(wire, msg);
        up.decrypt_client(&mut wire);
        assert_eq!(wire, msg, "proxy sees plaintext in the middle");
        up.encrypt_upstream(&mut wire);
        tg_dec_of_proxy_output.apply_keystream(&mut wire);
        assert_eq!(wire, msg, "telegram decrypts the relayed stream");

        // telegram → client (two chunks to exercise keystream continuity)
        for reply in [&b"first reply"[..], &b"second reply, a bit longer"[..]] {
            let mut data = reply.to_vec();
            tg_enc_towards_proxy.apply_keystream(&mut data);
            down.reencrypt(&mut data);
            c_dec.apply_keystream(&mut data);
            assert_eq!(data, reply);
        }
    }

    #[test]
    fn socks_mode_patch_dc_keeps_stream_valid() {
        let mut init = generate_relay_init(PROTO_ABRIDGED, 7);
        assert_eq!(peek_client_init(&init).unwrap().dc_raw, 7);
        patch_dc(&mut init, 2, true);
        let hs = peek_client_init(&init).unwrap();
        assert_eq!(hs.dc_raw, -2);
        assert_eq!(hs.proto, PROTO_ABRIDGED);
        patch_dc(&mut init, 4, false);
        assert_eq!(peek_client_init(&init).unwrap().dc_raw, 4);
        assert!(stream_decryptor(&init).is_some());
    }

    fn feed(sp: &mut MsgSplitter, stream: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for c in stream.chunks(chunk) {
            // distinct "ciphertext" so we can tell which buffer slices come from
            let cipher: Vec<u8> = c.iter().map(|b| b ^ 0x55).collect();
            out.extend(sp.split(c, &cipher));
        }
        out
    }

    fn unxor(parts: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        parts.into_iter().map(|p| p.into_iter().map(|b| b ^ 0x55).collect()).collect()
    }

    #[test]
    fn splitter_abridged() {
        let p1 = [vec![3u8], vec![1u8; 12]].concat(); // 3*4 payload
        let p2 = [vec![0x7Fu8, 40, 0, 0], vec![2u8; 160]].concat(); // long form
        let p3 = [vec![0x80 | 1u8], vec![3u8; 4]].concat(); // quick-ack bit set
        let stream = [p1.clone(), p2.clone(), p3.clone()].concat();
        for chunk in [1, 3, 7, 64, 1000] {
            let mut sp = MsgSplitter::new(PROTO_ABRIDGED);
            let parts = unxor(feed(&mut sp, &stream, chunk));
            assert_eq!(parts, vec![p1.clone(), p2.clone(), p3.clone()], "chunk={chunk}");
            assert!(sp.flush().is_none());
        }
    }

    #[test]
    fn splitter_intermediate_and_padded() {
        let mk = |n: u32, fill: u8| [n.to_le_bytes().to_vec(), vec![fill; n as usize]].concat();
        let (a, b, c) = (mk(16, 1), mk(8, 2), mk(40, 3));
        let stream = [a.clone(), b.clone(), c.clone()].concat();
        for proto in [PROTO_INTERMEDIATE, PROTO_PADDED] {
            for chunk in [1, 5, 33, 4096] {
                let mut sp = MsgSplitter::new(proto);
                assert_eq!(
                    unxor(feed(&mut sp, &stream, chunk)),
                    vec![a.clone(), b.clone(), c.clone()],
                    "proto={proto:x} chunk={chunk}"
                );
            }
        }
    }

    #[test]
    fn splitter_buffers_partial_and_flushes() {
        let pkt = [vec![2u8], vec![9u8; 8]].concat();
        let mut sp = MsgSplitter::new(PROTO_ABRIDGED);
        let cipher: Vec<u8> = pkt[..5].iter().map(|b| b ^ 0x55).collect();
        assert!(sp.split(&pkt[..5], &cipher).is_empty());
        assert_eq!(sp.flush().unwrap().len(), 5);
        assert!(sp.flush().is_none());
    }

    #[test]
    fn splitter_disables_on_garbage() {
        let mut sp = MsgSplitter::new(PROTO_INTERMEDIATE);
        // zero-length packet is invalid → forward everything, forever
        let junk = [0u8; 16];
        let parts = sp.split(&junk, &junk);
        assert_eq!(parts, vec![junk.to_vec()]);
        let more = [5u8; 9];
        assert_eq!(sp.split(&more, &more), vec![more.to_vec()]);

        // absurd length must not make us buffer unboundedly
        let mut sp = MsgSplitter::new(PROTO_INTERMEDIATE);
        let huge = 0x7FFF_FFF0u32.to_le_bytes();
        assert_eq!(sp.split(&huge, &huge).len(), 1);
    }
}
