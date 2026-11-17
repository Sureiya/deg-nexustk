//! The documented NexusTK 7.52 wire codec: key table, temp key, tail
//! encode/decode, the self-inverse 3-stage XOR body transform, framing
//! policy, and frame assembly/parsing.
//!
//! Everything here is implemented from the documented algorithms (see
//! `README.md`); the committed synthetic fixtures cross-check this
//! code against an independent Python implementation of the same algorithm
//! (`tools/gen_fixtures.py`).

use crate::md5::md5_hex;

/// The 7.52 static body key `"Urk#nI7ni"` (55 72 6B 23 6E 49 37 6E 69).
pub const STATIC_KEY_752: [u8; 9] = [0x55, 0x72, 0x6B, 0x23, 0x6E, 0x49, 0x37, 0x6E, 0x69];

/// The 7.52 client-side send cap: the client's assembly buffer is 40,000
/// bytes, so no outbound frame may total more than 39,990 wire bytes.
pub const MAX_SEND_FRAME_BYTES_752: usize = 39_990;

/// The absolute u16 wire cap: 3 header bytes plus a 16-bit length field.
pub const ABSOLUTE_MAX_FRAME_BYTES: usize = 65_538;

/// Sender direction of the bytes being read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    C2S,
    S2C,
}

impl Direction {
    pub fn parse(s: &str) -> Option<Direction> {
        match s {
            "c2s" => Some(Direction::C2S),
            "s2c" => Some(Direction::S2C),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Direction::C2S => "c2s",
            Direction::S2C => "s2c",
        }
    }
}

/// The socket peer classification carried by a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Login,
    Game,
}

impl Channel {
    pub fn parse(s: &str) -> Option<Channel> {
        match s {
            "login" => Some(Channel::Login),
            "game" => Some(Channel::Game),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Login => "login",
            Channel::Game => "game",
        }
    }
}

/// The 1024-byte ASCII-hex key table derived from a character name.
///
/// ```text
/// h0 = md5_hex(name)
/// h1 = md5_hex(h0)
/// t  = h1
/// while len(t) < 1024: t += md5_hex(t)   # each hash covers the whole
///                                        # accumulated string so far
/// table = t[0:1024]
/// ```
///
/// The name is case-sensitive and is the exact spelling sent on the wire.
/// Only the first 1024 bytes are key data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTable {
    table: [u8; 1024],
}

impl KeyTable {
    pub fn new(name: &str) -> KeyTable {
        let h0 = md5_hex(name.as_bytes());
        let h1 = md5_hex(h0.as_bytes());
        let mut t = h1.into_bytes();
        while t.len() < 1024 {
            t.extend_from_slice(md5_hex(&t).as_bytes());
        }
        t.truncate(1024);
        let mut table = [0u8; 1024];
        table.copy_from_slice(&t);
        KeyTable { table }
    }

    /// The full 1024 table bytes (ASCII hex digits). Not emitted into facts
    /// or details; key material.
    pub fn as_bytes(&self) -> &[u8; 1024] {
        &self.table
    }

    /// The per-frame 9-byte key selected by `(b8, w16)`.
    ///
    /// ```text
    /// ecx = b8*b8
    /// for i in 0..9:
    ///     key[i] = table[(ecx*i + w16) & 0x3FF]
    ///     ecx += 3
    /// ```
    pub fn temp_key(&self, b8: u8, w16: u16) -> [u8; 9] {
        let mut ecx = u32::from(b8) * u32::from(b8);
        let mut key = [0u8; 9];
        for (i, slot) in key.iter_mut().enumerate() {
            let idx = (ecx * i as u32 + u32::from(w16)) & 0x3FF;
            *slot = self.table[idx as usize];
            ecx += 3;
        }
        key
    }
}

/// The two key-selection parameters encoded by the 3 tail bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailParams {
    pub b8: u8,
    pub w16: u16,
}

/// Encode tail parameters for a C2S frame:
/// `[w16.lo ^ 0x61, b8 ^ 0x25, w16.hi ^ 0x23]`.
pub fn encode_tail_c2s(p: TailParams) -> [u8; 3] {
    [(p.w16 as u8) ^ 0x61, p.b8 ^ 0x25, (p.w16 >> 8) as u8 ^ 0x23]
}

/// Encode tail parameters for an S2C frame:
/// `[w16.lo ^ 0x24, b8 ^ 0x21, w16.hi ^ 0x74]`.
pub fn encode_tail_s2c(p: TailParams) -> [u8; 3] {
    [(p.w16 as u8) ^ 0x24, p.b8 ^ 0x21, (p.w16 >> 8) as u8 ^ 0x74]
}

/// Decode a C2S tail: `b8 = tail[1] ^ 0x25`,
/// `w16 = ((tail[2]^0x23) << 8) | (tail[0]^0x61)`.
pub fn decode_tail_c2s(tail: [u8; 3]) -> TailParams {
    TailParams {
        b8: tail[1] ^ 0x25,
        w16: (u16::from(tail[2] ^ 0x23) << 8) | u16::from(tail[0] ^ 0x61),
    }
}

/// Decode an S2C tail: `b8 = tail[1] ^ 0x21`,
/// `w16 = ((tail[2]^0x74) << 8) | (tail[0]^0x24)`.
pub fn decode_tail_s2c(tail: [u8; 3]) -> TailParams {
    TailParams {
        b8: tail[1] ^ 0x21,
        w16: (u16::from(tail[2] ^ 0x74) << 8) | u16::from(tail[0] ^ 0x24),
    }
}

/// Encode tail parameters for a sender direction.
pub fn encode_tail(dir: Direction, p: TailParams) -> [u8; 3] {
    match dir {
        Direction::C2S => encode_tail_c2s(p),
        Direction::S2C => encode_tail_s2c(p),
    }
}

/// Decode a sender-direction tail back into parameters.
pub fn decode_tail(dir: Direction, tail: [u8; 3]) -> TailParams {
    match dir {
        Direction::C2S => decode_tail_c2s(tail),
        Direction::S2C => decode_tail_s2c(tail),
    }
}

/// The self-inverse 3-stage XOR transform, applied in place. Static and
/// table ciphers share this core; only the key source differs.
///
/// ```text
/// for i in 0..len(body)-1:
///     body[i] ^= key[i % 9]
///     g = uint8(i / 9)          # 8-bit wrapped group counter
///     if g != inc:
///         body[i] ^= g
///     body[i] ^= inc
/// ```
///
/// The group comparison must use the 8-bit wrap: bodies over `9*256 = 2304`
/// bytes exercise it and must not use a full-width comparison.
pub fn crypt_in_place(body: &mut [u8], key: &[u8; 9], inc: u8) {
    for (i, byte) in body.iter_mut().enumerate() {
        *byte ^= key[i % 9];
        let g = (i / 9) as u8;
        if g != inc {
            *byte ^= g;
        }
        *byte ^= inc;
    }
}

/// A copy of `body` after the transform.
pub fn crypt(body: &[u8], key: &[u8; 9], inc: u8) -> Vec<u8> {
    let mut out = body.to_vec();
    crypt_in_place(&mut out, key, inc);
    out
}

/// Which body transform applies to one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Plain,
    Static,
    Table,
}

impl CipherKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CipherKind::Plain => "plain",
            CipherKind::Static => "static",
            CipherKind::Table => "table",
        }
    }
}

/// The framing layout of one opcode. Direction is the sender direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameShape {
    pub has_increment: bool,
    pub has_tail: bool,
    pub raw: bool,
}

impl FrameShape {
    /// The number of length-field bytes not occupied by the body: 1 for the
    /// opcode, +1 with an increment, +3 with a tail.
    pub fn len_bias(self) -> usize {
        1 + usize::from(self.has_increment) + 3 * usize::from(self.has_tail)
    }
}

/// The documented 7.52 framing exceptions: `0x00` (both directions), the S2C
/// `0x03` redirect, the `0x10` arrival, and the S2C `0x7E` welcome.
pub fn frame_shape(dir: Direction, opcode: u8) -> FrameShape {
    match opcode {
        0x00 => FrameShape {
            has_increment: false,
            has_tail: false,
            raw: true,
        },
        0x03 if dir == Direction::S2C => FrameShape {
            has_increment: false,
            has_tail: false,
            raw: true,
        },
        0x10 => FrameShape {
            has_increment: true,
            has_tail: false,
            raw: true,
        },
        0x7E => FrameShape {
            has_increment: false,
            has_tail: false,
            raw: true,
        },
        _ => FrameShape {
            has_increment: true,
            has_tail: true,
            raw: false,
        },
    }
}

/// The documented 7.52 cipher policy: plaintext opcodes per direction, the
/// static-key opcodes per direction, the login channel (always static for
/// encrypted frames), and the name table for everything else on the game
/// channel.
pub fn cipher_kind(channel: Channel, dir: Direction, opcode: u8) -> CipherKind {
    if frame_shape(dir, opcode).raw {
        return CipherKind::Plain;
    }
    let plain = match dir {
        Direction::C2S => matches!(opcode, 0x00 | 0x10 | 0x48),
        Direction::S2C => matches!(opcode, 0x00 | 0x03 | 0x40 | 0x7E),
    };
    if plain {
        return CipherKind::Plain;
    }
    if channel == Channel::Login {
        return CipherKind::Static;
    }
    let stat = match dir {
        Direction::C2S => matches!(
            opcode,
            0x02 | 0x03
                | 0x04
                | 0x0B
                | 0x15
                | 0x26
                | 0x3A
                | 0x42
                | 0x43
                | 0x4B
                | 0x50
                | 0x57
                | 0x62
                | 0x71
                | 0x73
                | 0x7B
        ),
        Direction::S2C => matches!(
            opcode,
            0x02 | 0x0A | 0x44 | 0x5E | 0x60 | 0x62 | 0x66 | 0x6F
        ),
    };
    if stat {
        CipherKind::Static
    } else {
        CipherKind::Table
    }
}

/// One parsed wire frame, with the still-encrypted body and its framing
/// classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFrame {
    pub opcode: u8,
    pub increment: u8,
    pub body: Vec<u8>,
    pub tail: [u8; 3],
    pub raw: bool,
    pub plaintext: bool,
    /// Total wire bytes of this frame (AA + length field included).
    pub wire_len: usize,
}

/// Framing errors. The vector replay checks "the codec rejects this wire",
/// so error vectors accept any class below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The first byte is not the `0xAA` frame magic.
    BadMagic(u8),
    /// The 16-bit length field has no room for the opcode, or the length is
    /// below the layout's bias.
    MalformedFrame(String),
    /// The frame (or the buffered stream) exceeds a configured limit.
    FrameTooLarge(String),
    /// More bytes are needed to complete the frame; not an error.
    NeedMore,
    /// The frame needs an identity for a table-cipher body but none was set.
    IdentityNeeded,
    /// The frame cannot be encoded within the documented 7.52 send cap.
    SendCapExceeded(String),
    /// Anything else the codec rejects.
    Other(String),
}

impl CodecError {
    /// True for the error classes a vector replay counts as "the codec
    /// rejected this wire" (everything except NeedMore, which is the
    /// "wait for more bytes" state).
    pub fn is_framing_error(&self) -> bool {
        !matches!(self, CodecError::NeedMore)
    }
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::BadMagic(b) => write!(f, "bad frame magic 0x{b:02X}"),
            CodecError::MalformedFrame(m) => write!(f, "malformed frame: {m}"),
            CodecError::FrameTooLarge(m) => write!(f, "frame too large: {m}"),
            CodecError::NeedMore => write!(f, "need more bytes"),
            CodecError::IdentityNeeded => write!(f, "identity needed for the table cipher"),
            CodecError::SendCapExceeded(m) => write!(f, "send cap exceeded: {m}"),
            CodecError::Other(m) => write!(f, "{m}"),
        }
    }
}

/// Decrypt the body of a parsed frame with the declared identity.
///
/// `identity` may be empty for plain/static frames; for table-cipher frames
/// it is the character name whose key table selects the per-frame key via
/// the decoded tail.
pub fn decrypt_body(
    channel: Channel,
    dir: Direction,
    opcode: u8,
    increment: u8,
    body: &[u8],
    tail: [u8; 3],
    identity: &str,
) -> Result<Vec<u8>, CodecError> {
    match cipher_kind(channel, dir, opcode) {
        CipherKind::Plain => Ok(body.to_vec()),
        CipherKind::Static => Ok(crypt(body, &STATIC_KEY_752, increment)),
        CipherKind::Table => {
            if identity.is_empty() {
                return Err(CodecError::IdentityNeeded);
            }
            let table = KeyTable::new(identity);
            let params = decode_tail(dir, tail);
            Ok(crypt(
                body,
                &table.temp_key(params.b8, params.w16),
                increment,
            ))
        }
    }
}

/// Encrypt a body for the wire with the declared identity, reusing the tail
/// bytes that select the per-frame table key (plain/static frames only carry
/// the tail; it does not select their key).
pub fn encrypt_body(
    channel: Channel,
    dir: Direction,
    opcode: u8,
    increment: u8,
    body: &[u8],
    tail: [u8; 3],
    identity: &str,
) -> Result<Vec<u8>, CodecError> {
    match cipher_kind(channel, dir, opcode) {
        CipherKind::Plain => Ok(body.to_vec()),
        CipherKind::Static => Ok(crypt(body, &STATIC_KEY_752, increment)),
        CipherKind::Table => {
            if identity.is_empty() {
                return Err(CodecError::IdentityNeeded);
            }
            let table = KeyTable::new(identity);
            let params = decode_tail(dir, tail);
            Ok(crypt(
                body,
                &table.temp_key(params.b8, params.w16),
                increment,
            ))
        }
    }
}

/// Assemble the wire bytes of one frame:
/// `AA | len(u16 BE) | opcode | [inc] | body | [tail 3]`, where `len` counts
/// opcode + increment + body + tail. `body` must already be the wire form
/// (encrypted, or verbatim for plain/raw frames).
pub fn build_wire(
    dir: Direction,
    opcode: u8,
    increment: u8,
    body: &[u8],
    tail: [u8; 3],
) -> Result<Vec<u8>, CodecError> {
    let shape = frame_shape(dir, opcode);
    let n = shape.len_bias() + body.len();
    if n > 65_535 {
        return Err(CodecError::FrameTooLarge(format!(
            "length field would be {n}"
        )));
    }
    let total = 3 + n;
    if total > MAX_SEND_FRAME_BYTES_752 {
        return Err(CodecError::SendCapExceeded(format!(
            "total {total} bytes exceeds the 7.52 send cap {MAX_SEND_FRAME_BYTES_752}"
        )));
    }
    let mut wire = Vec::with_capacity(total);
    wire.push(0xAA);
    wire.extend_from_slice(&(n as u16).to_be_bytes());
    wire.push(opcode);
    if shape.has_increment {
        wire.push(increment);
    }
    wire.extend_from_slice(body);
    if shape.has_tail {
        wire.extend_from_slice(&tail);
    }
    Ok(wire)
}

/// Parse one frame from the front of `data`. Returns the frame and the total
/// wire length consumed. `NeedMore` means the buffer does not yet hold a
/// complete frame. `max_frame_bytes` is the configurable wire cap (the u16
/// length field itself caps frames at 65,538 bytes).
pub fn parse_frame(
    channel: Channel,
    dir: Direction,
    data: &[u8],
    max_frame_bytes: usize,
) -> Result<(ParsedFrame, usize), CodecError> {
    if data.is_empty() {
        return Err(CodecError::NeedMore);
    }
    if data[0] != 0xAA {
        return Err(CodecError::BadMagic(data[0]));
    }
    if data.len() < 3 {
        return Err(CodecError::NeedMore);
    }
    let n = u16::from_be_bytes([data[1], data[2]]) as usize;
    let total = 3 + n;
    if total > max_frame_bytes {
        return Err(CodecError::FrameTooLarge(format!(
            "length {n} total {total} (limit {max_frame_bytes})"
        )));
    }
    if n < 1 {
        return Err(CodecError::MalformedFrame(format!(
            "length {n} has no opcode"
        )));
    }
    if data.len() < total {
        return Err(CodecError::NeedMore);
    }

    let opcode = data[3];
    let shape = frame_shape(dir, opcode);
    if n < shape.len_bias() {
        return Err(CodecError::MalformedFrame(format!(
            "opcode 0x{opcode:02X} length {n} is below layout bias {}",
            shape.len_bias()
        )));
    }
    let mut pos = 4;
    let mut increment = 0u8;
    if shape.has_increment {
        increment = data[pos];
        pos += 1;
    }
    let mut end = total;
    let mut tail = [0u8; 3];
    if shape.has_tail {
        end -= 3;
        tail.copy_from_slice(&data[end..end + 3]);
    }
    let body = data[pos..end].to_vec();
    let plaintext = cipher_kind(channel, dir, opcode) == CipherKind::Plain;
    Ok((
        ParsedFrame {
            opcode,
            increment,
            body,
            tail,
            raw: shape.raw,
            plaintext,
            wire_len: total,
        },
        total,
    ))
}

/// Incremental framer: splits a byte stream into frames, tolerating partial
/// and concatenated frames. It performs no decryption.
pub struct Framer {
    channel: Channel,
    dir: Direction,
    max_frame_bytes: usize,
    max_assembly_bytes: usize,
    buf: Vec<u8>,
}

impl Framer {
    pub fn new(channel: Channel, dir: Direction, max_frame_bytes: usize) -> Framer {
        let max_frame_bytes = if max_frame_bytes == 0 {
            ABSOLUTE_MAX_FRAME_BYTES
        } else {
            max_frame_bytes
        };
        Framer {
            channel,
            dir,
            max_frame_bytes,
            max_assembly_bytes: 2 * max_frame_bytes + 65_536,
            buf: Vec::new(),
        }
    }

    /// Append wire bytes to the assembly buffer.
    pub fn feed(&mut self, p: &[u8]) -> Result<(), CodecError> {
        if p.is_empty() {
            return Ok(());
        }
        if self.buf.len() + p.len() > self.max_assembly_bytes {
            return Err(CodecError::FrameTooLarge(format!(
                "assembly buffer would reach {} bytes (limit {})",
                self.buf.len() + p.len(),
                self.max_assembly_bytes
            )));
        }
        self.buf.extend_from_slice(p);
        Ok(())
    }

    /// Bytes not yet consumed.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The next complete frame, or `NeedMore` when more bytes are required.
    pub fn next_frame(&mut self) -> Result<(ParsedFrame, usize), CodecError> {
        let (frame, consumed) =
            parse_frame(self.channel, self.dir, &self.buf, self.max_frame_bytes)?;
        self.buf.drain(..consumed);
        Ok((frame, consumed))
    }
}

/// Decode all complete frames in `data` and return them plus the number of
/// bytes consumed. A trailing partial frame is left unconsumed and is not an
/// error. Bodies are decrypted with the declared identity.
pub fn decode_stream(
    channel: Channel,
    dir: Direction,
    data: &[u8],
    identity: &str,
    max_frame_bytes: usize,
) -> Result<(Vec<DecodedFrame>, usize), CodecError> {
    let mut framer = Framer::new(channel, dir, max_frame_bytes);
    framer.feed(data)?;
    let mut frames = Vec::new();
    loop {
        let (parsed, _) = match framer.next_frame() {
            Ok(v) => v,
            Err(CodecError::NeedMore) => break,
            Err(e) => return Err(e),
        };
        let body = decrypt_body(
            channel,
            dir,
            parsed.opcode,
            parsed.increment,
            &parsed.body,
            parsed.tail,
            identity,
        )?;
        frames.push(DecodedFrame {
            opcode: parsed.opcode,
            increment: parsed.increment,
            body,
            tail: parsed.tail,
            raw: parsed.raw,
        });
    }
    Ok((frames, data.len() - framer.buffered()))
}

/// One decrypted frame from a stream decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub opcode: u8,
    pub increment: u8,
    pub body: Vec<u8>,
    pub tail: [u8; 3],
    pub raw: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-computed vectors produced by the committed generator
    /// `tools/gen_fixtures.py` (independent Python implementation of
    /// the documented algorithm; the committed `vectors-synthetic.json`
    /// carries the same values).
    mod gen {
        include!("../tests/gen_data/mod.rs");
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn key_table_matches_generated_prefix_and_is_deterministic() {
        let table = KeyTable::new("deg-vector-a");
        let prefix = String::from_utf8_lossy(&table.as_bytes()[..64]);
        assert_eq!(prefix, gen::KEYTABLE_DEG_VECTOR_A_PREFIX);
        assert_eq!(KeyTable::new("deg-vector-a"), table);
        assert!(table.as_bytes().iter().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn temp_key_matches_generated_value() {
        let table = KeyTable::new("deg-vector-a");
        let key = table.temp_key(gen::TEMPKEY_B8, gen::TEMPKEY_W16);
        assert_eq!(String::from_utf8_lossy(&key), gen::TEMPKEY_KEY);
    }

    #[test]
    fn tail_round_trips_both_directions() {
        let p = TailParams {
            b8: gen::TEMPKEY_B8,
            w16: gen::TEMPKEY_W16,
        };
        let c2s = encode_tail_c2s(p);
        assert_eq!(decode_tail_c2s(c2s), p);
        let s2c = encode_tail_s2c(p);
        assert_eq!(decode_tail_s2c(s2c), p);
        assert_eq!(encode_tail(Direction::C2S, p), c2s);
        assert_eq!(encode_tail(Direction::S2C, p), s2c);
        assert_eq!(decode_tail(Direction::C2S, c2s), p);
        assert_eq!(decode_tail(Direction::S2C, s2c), p);
    }

    #[test]
    fn tail_bytes_match_generated_hex() {
        let p = TailParams {
            b8: 0xDE,
            w16: 0xCAFE,
        };
        assert_eq!(hex(gen::TAIL_C2S_DE_CAFE), encode_tail_c2s(p).to_vec());
        let q = TailParams {
            b8: 0xAB,
            w16: 0xBEEF,
        };
        assert_eq!(hex(gen::TAIL_S2C_AB_BEEF), encode_tail_s2c(q).to_vec());
    }

    #[test]
    fn static_crypt_matches_generated_ciphertext() {
        let pt = hex(gen::CIPHER_STATIC_PT);
        let ct = crypt(&pt, &STATIC_KEY_752, gen::CIPHER_STATIC_INC);
        assert_eq!(hex(gen::CIPHER_STATIC_CT), ct);
        // Self-inverse.
        assert_eq!(crypt(&ct, &STATIC_KEY_752, gen::CIPHER_STATIC_INC), pt);
    }

    #[test]
    fn table_crypt_matches_generated_ciphertext() {
        let pt = hex(gen::CIPHER_TABLE_PT);
        let table = KeyTable::new("deg-vector-a");
        let tail = decode_tail_s2c([
            gen::CIPHER_TABLE_TAIL[0],
            gen::CIPHER_TABLE_TAIL[1],
            gen::CIPHER_TABLE_TAIL[2],
        ]);
        let key = table.temp_key(tail.b8, tail.w16);
        let ct = crypt(&pt, &key, gen::CIPHER_TABLE_INC);
        assert_eq!(hex(gen::CIPHER_TABLE_CT), ct);
        assert_eq!(crypt(&ct, &key, gen::CIPHER_TABLE_INC), pt);
    }

    #[test]
    fn group_counter_wraps_at_8_bits() {
        // A 2305-byte body crosses group 256; the comparison must use the
        // 8-bit wrapped value so byte 2304 (g=0) is XORed with the group term
        // only when inc!=0. The plaintext is the vector convention pattern
        // `(i*7+3) & 0xff`; the expected digest is the generated long-vector
        // ciphertext digest.
        let mut body = vec![0u8; 2305];
        for (i, b) in body.iter_mut().enumerate() {
            *b = ((i * 7 + 3) & 0xff) as u8;
        }
        let table = KeyTable::new("deg-vector-a");
        let tail = decode_tail_s2c([gen::LONG_TAIL[0], gen::LONG_TAIL[1], gen::LONG_TAIL[2]]);
        let key = table.temp_key(tail.b8, tail.w16);
        let ct = crypt(&body, &key, gen::LONG_INC);
        assert_eq!(deg::sha256::sha256_hex(&ct), gen::LONG_CT_SHA256);
        // Self-inverse across the wrap boundary.
        assert_eq!(crypt(&ct, &key, gen::LONG_INC), body);
    }

    #[test]
    fn frame_wire_matches_generated_bytes() {
        let wire = build_wire(
            Direction::C2S,
            0x62,
            0,
            &hex(gen::CIPHER_STATIC_CT),
            [
                gen::FRAME_STATIC_TAIL[0],
                gen::FRAME_STATIC_TAIL[1],
                gen::FRAME_STATIC_TAIL[2],
            ],
        )
        .unwrap();
        assert_eq!(hex(gen::FRAME_STATIC_WIRE), wire);

        let (parsed, consumed) = parse_frame(
            Channel::Login,
            Direction::C2S,
            &hex(gen::FRAME_STATIC_WIRE),
            ABSOLUTE_MAX_FRAME_BYTES,
        )
        .unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(parsed.opcode, 0x62);
        assert_eq!(parsed.increment, 0);
        assert_eq!(parsed.body, hex(gen::CIPHER_STATIC_CT));
        assert!(!parsed.raw);
        assert!(!parsed.plaintext);
    }

    #[test]
    fn raw_frame_wire_has_no_increment_or_tail() {
        let wire = build_wire(
            Direction::C2S,
            0x00,
            0,
            &hex(gen::FRAME_RAW_PLAINTEXT),
            [0, 0, 0],
        )
        .unwrap();
        assert_eq!(hex(gen::FRAME_RAW_WIRE), wire);
        let (parsed, consumed) = parse_frame(
            Channel::Login,
            Direction::C2S,
            &wire,
            ABSOLUTE_MAX_FRAME_BYTES,
        )
        .unwrap();
        assert_eq!(consumed, wire.len());
        assert!(parsed.raw);
        assert!(parsed.plaintext);
        assert_eq!(parsed.body, hex(gen::FRAME_RAW_PLAINTEXT));
        assert_eq!(parsed.tail, [0, 0, 0]);
    }

    #[test]
    fn arrival_frame_is_raw_with_increment() {
        let shape = frame_shape(Direction::C2S, 0x10);
        assert!(shape.raw);
        assert!(shape.has_increment);
        assert!(!shape.has_tail);
    }

    #[test]
    fn decode_stream_handles_concatenation_and_partial_frames() {
        let wire = hex(gen::STREAM_WIRE);
        let (frames, consumed) = decode_stream(
            Channel::Login,
            Direction::S2C,
            &wire,
            "",
            ABSOLUTE_MAX_FRAME_BYTES,
        )
        .unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(frames.len(), gen::STREAM_FRAME_COUNT);
        assert_eq!(frames[0].opcode, 0x00);
        assert!(frames[0].raw);
        assert_eq!(frames[1].opcode, 0x7E);
        assert_eq!(frames[2].opcode, 0x02);
        assert_eq!(frames[2].body, hex(gen::STREAM_FRAME2_PLAINTEXT));

        // Every split point still parses the same single first frame.
        let single = hex(gen::FRAME_STATIC_WIRE);
        for split in 0..=single.len() {
            let mut framer = Framer::new(Channel::Login, Direction::C2S, 0);
            framer.feed(&single[..split]).unwrap();
            let first = framer.next_frame();
            let parsed = if split < single.len() {
                assert_eq!(first, Err(CodecError::NeedMore));
                framer.feed(&single[split..]).unwrap();
                framer.next_frame().unwrap().0
            } else {
                first.unwrap().0
            };
            assert_eq!(parsed.opcode, 0x62);
        }
    }

    #[test]
    fn parse_rejects_bad_magic_and_oversized_frames() {
        let err = parse_frame(
            Channel::Game,
            Direction::S2C,
            &hex(gen::ERROR_BAD_MAGIC_WIRE),
            ABSOLUTE_MAX_FRAME_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, CodecError::BadMagic(gen::ERROR_BAD_MAGIC_BYTE));

        assert!(matches!(
            parse_frame(
                Channel::Game,
                Direction::S2C,
                &hex(gen::ERROR_OVER_LIMIT_WIRE),
                gen::ERROR_OVER_LIMIT_MAX,
            ),
            Err(CodecError::FrameTooLarge(_))
        ));

        // A length of zero has no room for an opcode.
        assert!(matches!(
            parse_frame(Channel::Game, Direction::S2C, &hex("aa0000"), 1024),
            Err(CodecError::MalformedFrame(_))
        ));
    }

    #[test]
    fn encode_enforces_the_752_send_cap() {
        let err = build_wire(Direction::S2C, 0x1E, 0, &vec![0u8; 40_000], [0; 3]).unwrap_err();
        assert!(matches!(err, CodecError::SendCapExceeded(_)));
    }

    #[test]
    fn cipher_policy_matches_the_documented_tables() {
        // Login channel: every encrypted frame is static.
        assert_eq!(
            cipher_kind(Channel::Login, Direction::C2S, 0x62),
            CipherKind::Static
        );
        // Game channel: documented static sets.
        assert_eq!(
            cipher_kind(Channel::Game, Direction::C2S, 0x0B),
            CipherKind::Static
        );
        assert_eq!(
            cipher_kind(Channel::Game, Direction::S2C, 0x0A),
            CipherKind::Static
        );
        // Everything else on the game channel is the name table.
        assert_eq!(
            cipher_kind(Channel::Game, Direction::S2C, 0x0C),
            CipherKind::Table
        );
        // Documented plaintext opcodes.
        assert_eq!(
            cipher_kind(Channel::Game, Direction::S2C, 0x40),
            CipherKind::Plain
        );
        assert_eq!(
            cipher_kind(Channel::Game, Direction::C2S, 0x48),
            CipherKind::Plain
        );
    }
}
