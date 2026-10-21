//! Input decoding and output re-encoding (TRD §5.2).
//!
//! The decoder turns arbitrary byte chunks into validated UTF-8 text. Its results never depend
//! on how the input was chunked: a BOM is sniffed from at most 4 held-back bytes, a code point
//! split across chunks is completed by the next chunk, and every error is decided from the bytes
//! seen so far. On error, `out` holds the valid text decoded before the failure point.

use alloc::string::String;
use alloc::vec::Vec;

use crate::model::{
    CoreError, DetectedEncoding, EncodingKind, ErrorCode, InputEncoding, InvalidUtf8,
};

const BOM_UTF8: &[u8] = b"\xEF\xBB\xBF";
const BOM_UTF16LE: &[u8] = b"\xFF\xFE";
const BOM_UTF16BE: &[u8] = b"\xFE\xFF";
const BOM_UTF32LE: &[u8] = b"\xFF\xFE\x00\x00";
const BOM_UTF32BE: &[u8] = b"\x00\x00\xFE\xFF";

/// Streaming decoder from input bytes to validated UTF-8.
#[derive(Debug)]
pub struct Decoder {
    requested: InputEncoding,
    invalid: InvalidUtf8,
    detected: Option<DetectedEncoding>,
    /// BOM-sniffing bytes before detection; afterwards an incomplete UTF-8 sequence (≤ 3 bytes).
    pending: Vec<u8>,
    /// UTF-16: a byte waiting for its pair.
    odd: Option<u8>,
    /// UTF-16: a high surrogate waiting for its low surrogate.
    high: Option<u16>,
    /// UTF-8: bytes consumed after any BOM, used to classify a NUL (see `nul_error`).
    utf8_pos: u64,
    replaced: u64,
}

impl Decoder {
    pub fn new(requested: InputEncoding, invalid: InvalidUtf8) -> Self {
        Self {
            requested,
            invalid,
            detected: None,
            pending: Vec::new(),
            odd: None,
            high: None,
            utf8_pos: 0,
            replaced: 0,
        }
    }

    /// True once the input encoding has been decided.
    pub fn is_detected(&self) -> bool {
        self.detected.is_some()
    }

    /// Bytes held back before detection or inside an incomplete sequence.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Zeroes held-back input bytes (TRD §10.5, §11.4).
    pub fn wipe(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.pending);
        self.odd = None;
        self.high = None;
    }

    /// The input encoding; UTF-8 without BOM until something else is detected.
    pub fn detected(&self) -> DetectedEncoding {
        self.detected.unwrap_or(DetectedEncoding {
            kind: EncodingKind::Utf8,
            bom: false,
        })
    }

    /// Invalid UTF-8 sequences replaced by U+FFFD (only with `InvalidUtf8::Replace`).
    pub fn invalid_replaced(&self) -> u64 {
        self.replaced
    }

    /// Decodes a chunk, appending complete text to `out`.
    pub fn decode(&mut self, input: &[u8], out: &mut String) -> Result<(), CoreError> {
        let mut rest = input;
        if self.detected.is_none() {
            while self.detected.is_none() {
                if self.sniff(false)? {
                    break;
                }
                let Some((&b, tail)) = rest.split_first() else {
                    return Ok(());
                };
                self.pending.push(b);
                rest = tail;
            }
            let held = core::mem::take(&mut self.pending);
            self.feed(&held, out)?;
        }
        self.feed(rest, out)
    }

    /// Ends the stream: flushes or rejects any incomplete sequence.
    pub fn finish(&mut self, out: &mut String) -> Result<(), CoreError> {
        if self.detected.is_none() {
            self.sniff(true)?;
            let held = core::mem::take(&mut self.pending);
            self.feed(&held, out)?;
        }
        match self.detected().kind {
            EncodingKind::Utf8 => {
                if !self.pending.is_empty() {
                    self.pending.clear();
                    match self.invalid {
                        InvalidUtf8::Error => return Err(CoreError::new(ErrorCode::InvalidUtf8)),
                        InvalidUtf8::Replace => {
                            out.push('\u{FFFD}');
                            self.replaced = self.replaced.saturating_add(1);
                        }
                    }
                }
            }
            EncodingKind::Utf16Le | EncodingKind::Utf16Be => {
                if self.odd.is_some() || self.high.is_some() {
                    return Err(CoreError::new(ErrorCode::InvalidUtf16));
                }
            }
        }
        Ok(())
    }

    /// Decides the encoding from the held-back bytes. Returns `Ok(false)` when more bytes are
    /// needed. On success the held bytes are left in `pending` minus any BOM.
    fn sniff(&mut self, at_eof: bool) -> Result<bool, CoreError> {
        let p = self.pending.as_slice();
        let candidates: &[&[u8]] = match self.requested {
            InputEncoding::Auto => &[BOM_UTF8, BOM_UTF32LE, BOM_UTF32BE, BOM_UTF16LE, BOM_UTF16BE],
            InputEncoding::Utf8 => &[BOM_UTF8],
            InputEncoding::Utf16Le => &[BOM_UTF16LE],
            InputEncoding::Utf16Be => &[BOM_UTF16BE],
        };
        // Wait while the held bytes are a proper prefix of a BOM that could still match.
        if !at_eof
            && candidates
                .iter()
                .any(|bom| bom.len() > p.len() && bom.starts_with(p))
        {
            return Ok(false);
        }
        let (kind, bom_len) = match self.requested {
            InputEncoding::Auto => {
                if p.starts_with(BOM_UTF8) {
                    (EncodingKind::Utf8, BOM_UTF8.len())
                } else if p.starts_with(BOM_UTF32LE) || p.starts_with(BOM_UTF32BE) {
                    return Err(CoreError::new(ErrorCode::UnsupportedEncoding));
                } else if p.starts_with(BOM_UTF16LE) {
                    (EncodingKind::Utf16Le, BOM_UTF16LE.len())
                } else if p.starts_with(BOM_UTF16BE) {
                    (EncodingKind::Utf16Be, BOM_UTF16BE.len())
                } else {
                    (EncodingKind::Utf8, 0)
                }
            }
            InputEncoding::Utf8 => (
                EncodingKind::Utf8,
                if p.starts_with(BOM_UTF8) { 3 } else { 0 },
            ),
            InputEncoding::Utf16Le => (
                EncodingKind::Utf16Le,
                if p.starts_with(BOM_UTF16LE) { 2 } else { 0 },
            ),
            InputEncoding::Utf16Be => (
                EncodingKind::Utf16Be,
                if p.starts_with(BOM_UTF16BE) { 2 } else { 0 },
            ),
        };
        self.pending.drain(..bom_len.min(self.pending.len()));
        self.detected = Some(DetectedEncoding {
            kind,
            bom: bom_len > 0,
        });
        Ok(true)
    }

    fn feed(&mut self, bytes: &[u8], out: &mut String) -> Result<(), CoreError> {
        match self.detected().kind {
            EncodingKind::Utf8 => self.feed_utf8(bytes, out),
            EncodingKind::Utf16Le => self.feed_utf16(bytes, out, u16::from_le_bytes),
            EncodingKind::Utf16Be => self.feed_utf16(bytes, out, u16::from_be_bytes),
        }
    }

    fn feed_utf8(&mut self, bytes: &[u8], out: &mut String) -> Result<(), CoreError> {
        let mut rest = bytes;
        // Complete a code point that was split across chunks.
        while !self.pending.is_empty() {
            let Some((&b, tail)) = rest.split_first() else {
                return Ok(());
            };
            rest = tail;
            self.pending.push(b);
            if is_incomplete_prefix(&self.pending) {
                continue;
            }
            let held = core::mem::take(&mut self.pending);
            self.feed_complete_utf8(&held, out)?;
        }
        self.feed_complete_utf8(rest, out)
    }

    /// Decodes bytes whose only possible incomplete sequence is at the very end.
    fn feed_complete_utf8(&mut self, bytes: &[u8], out: &mut String) -> Result<(), CoreError> {
        let mut chunks = bytes.utf8_chunks().peekable();
        while let Some(chunk) = chunks.next() {
            self.emit_utf8(chunk.valid(), out)?;
            let bad = chunk.invalid();
            if bad.is_empty() {
                continue;
            }
            if chunks.peek().is_none() && is_incomplete_prefix(bad) {
                self.pending.extend_from_slice(bad);
                return Ok(());
            }
            match self.invalid {
                InvalidUtf8::Error => return Err(CoreError::new(ErrorCode::InvalidUtf8)),
                InvalidUtf8::Replace => {
                    out.push('\u{FFFD}');
                    self.replaced = self.replaced.saturating_add(1);
                    self.utf8_pos = self.utf8_pos.saturating_add(len64(bad));
                }
            }
        }
        Ok(())
    }

    fn emit_utf8(&mut self, s: &str, out: &mut String) -> Result<(), CoreError> {
        if let Some(i) = memchr::memchr(0, s.as_bytes()) {
            out.push_str(s.get(..i).unwrap_or_default());
            let nul_pos = self
                .utf8_pos
                .saturating_add(len64(s.get(..i).unwrap_or_default().as_bytes()));
            return Err(nul_error(nul_pos, self.requested));
        }
        out.push_str(s);
        self.utf8_pos = self.utf8_pos.saturating_add(len64(s.as_bytes()));
        Ok(())
    }

    fn feed_utf16(
        &mut self,
        bytes: &[u8],
        out: &mut String,
        unit_of: fn([u8; 2]) -> u16,
    ) -> Result<(), CoreError> {
        let mut rest = bytes;
        if let Some(first) = self.odd {
            let Some((&second, tail)) = rest.split_first() else {
                return Ok(());
            };
            self.odd = None;
            rest = tail;
            self.push_unit(unit_of([first, second]), out)?;
        }
        let (pairs, remainder) = rest.as_chunks::<2>();
        for &pair in pairs {
            self.push_unit(unit_of(pair), out)?;
        }
        if let &[b] = remainder {
            self.odd = Some(b);
        }
        Ok(())
    }

    fn push_unit(&mut self, unit: u16, out: &mut String) -> Result<(), CoreError> {
        let is_high = (0xD800..=0xDBFF).contains(&unit);
        let is_low = (0xDC00..=0xDFFF).contains(&unit);
        let decoded = match self.high.take() {
            Some(high) if is_low => char::decode_utf16([high, unit]).next(),
            Some(_) => return Err(CoreError::new(ErrorCode::InvalidUtf16)),
            None if is_high => {
                self.high = Some(unit);
                return Ok(());
            }
            None if is_low => return Err(CoreError::new(ErrorCode::InvalidUtf16)),
            None => char::decode_utf16([unit]).next(),
        };
        match decoded {
            Some(Ok('\0')) => Err(CoreError::new(ErrorCode::NulByte)),
            Some(Ok(c)) => {
                out.push(c);
                Ok(())
            }
            _ => Err(CoreError::new(ErrorCode::InvalidUtf16)),
        }
    }
}

/// Classifies a NUL in UTF-8 input. ASCII-led UTF-16 without a byte-order mark always has a NUL
/// at offset 0 (big-endian) or 1 (little-endian); any later NUL is reported as binary input.
/// Deciding from the NUL's offset alone keeps the result independent of chunking. With UTF-8
/// requested explicitly there is nothing to hint at, so every NUL is binary input.
fn nul_error(offset: u64, requested: InputEncoding) -> CoreError {
    if offset <= 1 && requested == InputEncoding::Auto {
        CoreError::new(ErrorCode::Utf16WithoutBom)
    } else {
        CoreError::new(ErrorCode::NulByte)
    }
}

/// True when `b` is a proper prefix of some valid UTF-8 encoded scalar value.
fn is_incomplete_prefix(b: &[u8]) -> bool {
    let Some((&lead, cont)) = b.split_first() else {
        return false;
    };
    let (len, second): (usize, core::ops::RangeInclusive<u8>) = match lead {
        0xC2..=0xDF => (2, 0x80..=0xBF),
        0xE0 => (3, 0xA0..=0xBF),
        0xE1..=0xEC | 0xEE..=0xEF => (3, 0x80..=0xBF),
        0xED => (3, 0x80..=0x9F),
        0xF0 => (4, 0x90..=0xBF),
        0xF1..=0xF3 => (4, 0x80..=0xBF),
        0xF4 => (4, 0x80..=0x8F),
        _ => return false,
    };
    if b.len() >= len {
        return false;
    }
    cont.iter().enumerate().all(|(i, c)| {
        if i == 0 {
            second.contains(c)
        } else {
            (0x80..=0xBF).contains(c)
        }
    })
}

fn len64(b: &[u8]) -> u64 {
    u64::try_from(b.len()).unwrap_or(u64::MAX)
}

/// Re-encodes sanitized UTF-8 into the input's encoding (TRD §5.2: output uses the input's
/// encoding, and a BOM is re-emitted if and only if the input had one).
#[derive(Debug, Clone, Copy)]
pub struct Encoder {
    encoding: DetectedEncoding,
}

impl Encoder {
    pub fn new(encoding: DetectedEncoding) -> Self {
        Self { encoding }
    }

    pub fn bom(&self) -> &'static [u8] {
        if !self.encoding.bom {
            return b"";
        }
        match self.encoding.kind {
            EncodingKind::Utf8 => BOM_UTF8,
            EncodingKind::Utf16Le => BOM_UTF16LE,
            EncodingKind::Utf16Be => BOM_UTF16BE,
        }
    }

    pub fn encode(&self, s: &str, out: &mut Vec<u8>) {
        match self.encoding.kind {
            EncodingKind::Utf8 => out.extend_from_slice(s.as_bytes()),
            EncodingKind::Utf16Le => out.extend(s.encode_utf16().flat_map(u16::to_le_bytes)),
            EncodingKind::Utf16Be => out.extend(s.encode_utf16().flat_map(u16::to_be_bytes)),
        }
    }
}
