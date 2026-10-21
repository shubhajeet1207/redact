//! Terminal rendering (TRD §9.5). When display escaping is on, hidden and control characters
//! become visible `<U+XXXX>` markers and a lone CR becomes `<CR>` plus a line feed, so escape
//! sequences cannot drive the terminal and text cannot be visually overwritten. The engine's
//! census table decides which characters are hidden, so every surface marks the same set.

use std::fmt::Write as _;

use spymonk_redact_core::EncodingKind;
use spymonk_redact_core::census::hidden_kind;

#[derive(Debug, Default)]
pub struct Escaper {
    started: bool,
    pending_cr: bool,
    /// UTF-16 output: a byte waiting for its pair, and a high surrogate waiting for its low half.
    odd: Option<u8>,
    high: Option<u16>,
}

impl Escaper {
    /// Renders one chunk of sanitized output, encoded as `kind`, as display text.
    pub fn push(&mut self, bytes: &[u8], kind: EncodingKind) -> String {
        let mut out = String::with_capacity(bytes.len());
        match kind {
            EncodingKind::Utf8 => {
                // Engine output is valid UTF-8 and always ends at a line boundary.
                for c in String::from_utf8_lossy(bytes).chars() {
                    self.char(c, &mut out);
                }
            }
            EncodingKind::Utf16Le | EncodingKind::Utf16Be => {
                for &b in bytes {
                    let Some(first) = self.odd.take() else {
                        self.odd = Some(b);
                        continue;
                    };
                    let unit = if kind == EncodingKind::Utf16Le {
                        u16::from_le_bytes([first, b])
                    } else {
                        u16::from_be_bytes([first, b])
                    };
                    let c = match self.high.take() {
                        Some(h) => char::decode_utf16([h, unit]).next().and_then(Result::ok),
                        None if (0xD800..0xDC00).contains(&unit) => {
                            self.high = Some(unit);
                            continue;
                        }
                        None => char::from_u32(u32::from(unit)),
                    };
                    self.char(c.unwrap_or('\u{FFFD}'), &mut out);
                }
            }
        }
        out
    }

    /// Flushes a trailing lone CR.
    pub fn finish(&mut self) -> String {
        let mut out = String::new();
        if std::mem::take(&mut self.pending_cr) {
            out.push_str("<CR>\n");
        }
        out
    }

    fn char(&mut self, c: char, out: &mut String) {
        if std::mem::take(&mut self.pending_cr) {
            if c == '\n' {
                out.push_str("\r\n");
                self.started = true;
                return;
            }
            out.push_str("<CR>\n");
        }
        match c {
            '\r' => self.pending_cr = true,
            '\t' | '\n' => out.push(c),
            // A leading byte-order mark is an encoding signature, not hidden content.
            '\u{FEFF}' if !self.started => out.push(c),
            c if hidden_kind(c).is_some() => {
                let _ = write!(out, "<U+{:04X}>", u32::from(c));
            }
            c => out.push(c),
        }
        self.started = true;
    }
}
