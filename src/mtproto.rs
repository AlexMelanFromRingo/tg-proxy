use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

type Aes256Ctr = Ctr128BE<Aes256>;

/// Extract DC ID from a 64-byte MTProto obfuscation init packet.
/// Returns `(dc_id, is_media)` or `None` if the packet is not valid MTProto obfuscated.
pub fn extract_dc(data: &[u8]) -> Option<(u8, bool)> {
    if data.len() < 64 {
        return None;
    }
    let key: [u8; 32] = data[8..40].try_into().ok()?;
    let iv: [u8; 16] = data[40..56].try_into().ok()?;

    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
    let mut keystream = [0u8; 64];
    cipher.apply_keystream(&mut keystream);

    // XOR the last 8 bytes of the init packet with the keystream at the same offset
    let plain: Vec<u8> = data[56..64]
        .iter()
        .zip(&keystream[56..64])
        .map(|(a, b)| a ^ b)
        .collect();

    let proto = u32::from_le_bytes(plain[0..4].try_into().ok()?);
    let dc_raw = i16::from_le_bytes(plain[4..6].try_into().ok()?);

    // Valid MTProto obfuscation protocol tags
    if matches!(proto, 0xEFEF_EFEF | 0xEEEE_EEEE | 0xDDDD_DDDD | 0xFEFE_FEFE) {
        let dc = dc_raw.unsigned_abs() as u8;
        if (1..=5).contains(&dc) {
            return Some((dc, dc_raw < 0));
        }
    }
    None
}

/// Patch the DC ID in a 64-byte MTProto obfuscation init packet.
/// `is_media=true` → negative dc_raw in packet (media servers).
/// `is_media=false` → positive dc_raw.
///
/// Fix vs original Python: Python had `dc if is_media else -dc` which was inverted.
pub fn patch_dc(data: &mut [u8], dc: u8, is_media: bool) {
    if data.len() < 64 || !(1..=5).contains(&dc) {
        return;
    }
    let dc_signed: i16 = if is_media { -(dc as i16) } else { dc as i16 };
    let new_dc = dc_signed.to_le_bytes();

    let key: [u8; 32] = match data[8..40].try_into() {
        Ok(k) => k,
        Err(_) => return,
    };
    let iv: [u8; 16] = match data[40..56].try_into() {
        Ok(i) => i,
        Err(_) => return,
    };

    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
    let mut keystream = [0u8; 64];
    cipher.apply_keystream(&mut keystream);

    data[60] = keystream[60] ^ new_dc[0];
    data[61] = keystream[61] ^ new_dc[1];
}

/// Stateful MTProto abridged message boundary splitter.
///
/// Telegram's WebSocket relay requires one MTProto message per WebSocket frame.
/// Mobile clients often batch multiple messages in a single TCP write.
/// This splitter finds message boundaries by decrypting the ciphertext and
/// returns the original ciphertext split at those boundaries.
pub struct MsgSplitter {
    cipher: Aes256Ctr,
    /// Buffered plaintext from previous incomplete parse
    plain_buf: Vec<u8>,
    /// Buffered ciphertext corresponding to plain_buf
    cipher_buf: Vec<u8>,
}

impl MsgSplitter {
    /// Create a new splitter from the 64-byte init packet.
    /// The splitter's keystream is advanced past the init packet.
    pub fn new(init: &[u8]) -> Option<Self> {
        if init.len() < 64 {
            return None;
        }
        let key: [u8; 32] = init[8..40].try_into().ok()?;
        let iv: [u8; 16] = init[40..56].try_into().ok()?;
        let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());

        // Advance past the 64-byte init packet
        let mut skip = [0u8; 64];
        cipher.apply_keystream(&mut skip);

        Some(Self {
            cipher,
            plain_buf: Vec::new(),
            cipher_buf: Vec::new(),
        })
    }

    /// Split `chunk` into individual MTProto messages.
    /// Returns ciphertext slices at message boundaries.
    /// Falls back to returning the whole chunk if boundaries cannot be determined.
    pub fn split<'a>(&mut self, chunk: &'a [u8]) -> Vec<Vec<u8>> {
        // Decrypt chunk to find message boundaries
        let mut plain_chunk = chunk.to_vec();
        self.cipher.apply_keystream(&mut plain_chunk);

        self.plain_buf.extend_from_slice(&plain_chunk);
        self.cipher_buf.extend_from_slice(chunk);

        let plain = &self.plain_buf;

        let mut boundaries: Vec<usize> = Vec::new();
        let mut pos = 0usize;

        loop {
            if pos >= plain.len() {
                break;
            }
            let first = plain[pos];
            let (header_len, msg_len) = if first == 0x7f {
                if pos + 4 > plain.len() {
                    // Incomplete header — stop parsing, keep buffered
                    break;
                }
                let len_bytes = [plain[pos + 1], plain[pos + 2], plain[pos + 3], 0];
                let msg_len = u32::from_le_bytes(len_bytes) as usize * 4;
                (4, msg_len)
            } else {
                (1, first as usize * 4)
            };

            if msg_len == 0 {
                // Invalid — stop splitting
                boundaries.clear();
                break;
            }

            let end = pos + header_len + msg_len;
            if end > plain.len() {
                // Message extends past buffer — keep buffered
                break;
            }
            pos = end;
            boundaries.push(pos);
        }

        if boundaries.len() <= 1 && pos == plain.len() {
            // No split needed or can't split; flush whole buffer
            let result = vec![self.cipher_buf.clone()];
            self.plain_buf.clear();
            self.cipher_buf.clear();
            return result;
        }

        if boundaries.is_empty() {
            // Keep buffering
            return vec![];
        }

        // Emit complete messages, keep remainder buffered
        let last = *boundaries.last().unwrap();
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(boundaries.len());
        let mut prev = 0;
        for b in &boundaries {
            parts.push(self.cipher_buf[prev..*b].to_vec());
            prev = *b;
        }

        // Keep unparsed remainder in buffers
        self.plain_buf = self.plain_buf[last..].to_vec();
        self.cipher_buf = self.cipher_buf[last..].to_vec();

        parts
    }

    /// Flush any remaining buffered data (call on connection close).
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            None
        } else {
            let data = self.cipher_buf.clone();
            self.plain_buf.clear();
            self.cipher_buf.clear();
            Some(data)
        }
    }
}
