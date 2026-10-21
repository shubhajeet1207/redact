//! Adapter logic independent of JavaScript, so it is tested natively: paste jobs, streaming file
//! jobs with a bounded preview, and UTF-8 to UTF-16 range conversion (TRD §7.3, §10.2, §10.4).

use spymonk_redact_core::{
    CoreError, DEFAULT_MAX_LINE_BYTES, EncodingKind, ErrorCode, Finding, InputEncoding,
    InvalidUtf8, Limits, Options, Sanitizer, Summary,
};
use zeroize::Zeroize;

/// Paste-mode input limit: 1 MiB of UTF-8 (TRD §10.2).
pub const PASTE_LIMIT_BYTES: usize = 1_048_576;
/// File-mode preview: the first 64 KiB of sanitized text (TRD §10.4).
pub const PREVIEW_BYTES: usize = 64 * 1024;

/// Converts findings (UTF-8 byte offsets into `text` after `bom_bytes` bytes of byte-order
/// mark) to flat `[start, end, rule]` triples of UTF-16 code-unit offsets into `text`, in one
/// linear pass. Findings must be sorted and disjoint, as the engine produces them.
pub fn utf16_ranges(text: &str, findings: &[Finding], bom_bytes: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(findings.len().saturating_mul(3));
    let mut chars = text.char_indices().peekable();
    let mut units: u32 = 0;
    let mut to_units = |byte: u64| -> u32 {
        let target = usize::try_from(byte)
            .unwrap_or(usize::MAX)
            .saturating_add(bom_bytes);
        while let Some((_, c)) = chars.next_if(|(i, _)| *i < target) {
            units = units.saturating_add(u32::try_from(c.len_utf16()).unwrap_or(2));
        }
        units
    };
    for f in findings {
        let start = to_units(f.start);
        let end = to_units(f.end);
        out.extend([start, end, u32::from(f.rule.0)]);
    }
    out
}

/// The result of one paste job.
#[derive(Debug)]
pub enum PasteOutcome {
    Done {
        output: String,
        /// Flat `[start, end, rule]` UTF-16 ranges of inserted placeholders.
        ranges: Vec<u32>,
        summary: Box<Summary>,
    },
    Failed(CoreError),
}

/// Sanitizes pasted text. The input buffer is zeroed before returning.
pub fn sanitize_paste(mut text: String, email: bool, private_ip: bool) -> PasteOutcome {
    let outcome = run_paste(&text, Options { email, private_ip });
    text.zeroize();
    outcome
}

fn run_paste(text: &str, options: Options) -> PasteOutcome {
    let limits = Limits {
        max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        max_total_bytes: Some(PASTE_LIMIT_BYTES as u64),
    };
    // Paste text is always UTF-8; a NUL is binary content, not a UTF-16 hint.
    let mut s = match Sanitizer::new(
        options,
        limits,
        InputEncoding::Utf8,
        InvalidUtf8::Error,
        true,
    ) {
        Ok(s) => s,
        Err(e) => return PasteOutcome::Failed(e),
    };
    let mut bytes = Vec::with_capacity(text.len());
    let summary = s
        .push(text.as_bytes(), &mut bytes)
        .and_then(|()| s.finish(&mut bytes));
    let summary = match summary {
        Ok(summary) => summary,
        Err(e) => {
            bytes.zeroize();
            return PasteOutcome::Failed(e);
        }
    };
    let findings = s.take_ranges();
    match String::from_utf8(bytes) {
        Ok(output) => {
            let bom = if summary.encoding.bom { 3 } else { 0 };
            let ranges = utf16_ranges(&output, &findings, bom);
            PasteOutcome::Done {
                output,
                ranges,
                summary: Box::new(summary),
            }
        }
        Err(e) => {
            e.into_bytes().zeroize();
            PasteOutcome::Failed(CoreError::new(ErrorCode::InternalError))
        }
    }
}

/// A streaming file job: sanitized output per chunk, plus a bounded preview of the start of the
/// sanitized text with its placeholder ranges.
#[derive(Debug)]
pub struct FileCore {
    sanitizer: Sanitizer,
    out: Vec<u8>,
    preview: String,
    preview_full: bool,
    /// UTF-16LE/BE output: a byte waiting for its pair while decoding the preview.
    odd: Option<u8>,
    /// UTF-16 output: a high surrogate waiting for its low surrogate.
    high: Option<u16>,
    bom_skipped: bool,
    /// Bytes of BOM at the start of the preview text (UTF-8 offsets exclude it).
    preview_bom: usize,
    findings: Vec<Finding>,
    summary: Option<Summary>,
}

impl FileCore {
    pub fn new(email: bool, private_ip: bool, max_line_bytes: u32) -> Result<Self, CoreError> {
        let limits = Limits {
            max_line_bytes,
            max_total_bytes: None,
        };
        Ok(Self {
            sanitizer: Sanitizer::new(
                Options { email, private_ip },
                limits,
                InputEncoding::Auto,
                InvalidUtf8::Error,
                true,
            )?,
            out: Vec::new(),
            preview: String::new(),
            preview_full: false,
            odd: None,
            high: None,
            bom_skipped: false,
            preview_bom: 0,
            findings: Vec::new(),
            summary: None,
        })
    }

    /// Sanitizes the next chunk and returns the complete output it produced.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.out.clear();
        let result = self.sanitizer.push(chunk, &mut self.out);
        self.collect();
        result.map(|()| core::mem::take(&mut self.out))
    }

    /// Flushes the last line; afterwards [`FileCore::summary`] is available.
    pub fn finish(&mut self) -> Result<Vec<u8>, CoreError> {
        self.out.clear();
        let result = self.sanitizer.finish(&mut self.out);
        self.collect();
        let summary = result?;
        self.summary = Some(summary);
        Ok(core::mem::take(&mut self.out))
    }

    pub fn summary(&self) -> Option<&Summary> {
        self.summary.as_ref()
    }

    /// The preview text and its flat UTF-16 `[start, end, rule]` placeholder ranges.
    pub fn preview(&self) -> (&str, Vec<u32>) {
        (
            &self.preview,
            utf16_ranges(&self.preview, &self.findings, self.preview_bom),
        )
    }

    /// Extends the preview from the new output and keeps only findings that lie inside it, so
    /// memory stays bounded however many placeholders the file has.
    fn collect(&mut self) {
        let ranges = self.sanitizer.take_ranges();
        if !self.preview_full {
            self.extend_preview();
        }
        let limit = self.preview.len().saturating_sub(self.preview_bom);
        self.findings.extend(
            ranges
                .into_iter()
                .filter(|f| usize::try_from(f.end).is_ok_and(|e| e <= limit)),
        );
    }

    fn extend_preview(&mut self) {
        // Borrow the output separately from the preview state it extends.
        let out = core::mem::take(&mut self.out);
        self.decode_into_preview(&out);
        self.out = out;
    }

    fn decode_into_preview(&mut self, out: &[u8]) {
        let encoding = self.sanitizer_encoding();
        let mut bytes = out;
        if !self.bom_skipped && !bytes.is_empty() {
            self.bom_skipped = true;
            let bom: &[u8] = match encoding {
                EncodingKind::Utf8 => b"\xEF\xBB\xBF",
                EncodingKind::Utf16Le => b"\xFF\xFE",
                EncodingKind::Utf16Be => b"\xFE\xFF",
            };
            if let Some(rest) = bytes.strip_prefix(bom) {
                bytes = rest;
                self.preview.push('\u{FEFF}');
                self.preview_bom = 3;
            }
        }
        match encoding {
            EncodingKind::Utf8 => {
                // Output is valid UTF-8 split only at line ends, so each chunk decodes alone.
                for c in String::from_utf8_lossy(bytes).chars() {
                    if !self.push_preview(c) {
                        return;
                    }
                }
            }
            EncodingKind::Utf16Le | EncodingKind::Utf16Be => {
                let le = encoding == EncodingKind::Utf16Le;
                for &b in bytes {
                    let Some(first) = self.odd.take() else {
                        self.odd = Some(b);
                        continue;
                    };
                    let unit = if le {
                        u16::from_le_bytes([first, b])
                    } else {
                        u16::from_be_bytes([first, b])
                    };
                    let decoded = match self.high.take() {
                        Some(h) => char::decode_utf16([h, unit]).next().and_then(Result::ok),
                        None if (0xD800..0xDC00).contains(&unit) => {
                            self.high = Some(unit);
                            continue;
                        }
                        None => char::from_u32(u32::from(unit)),
                    };
                    if !self.push_preview(decoded.unwrap_or('\u{FFFD}')) {
                        return;
                    }
                }
            }
        }
    }

    /// Appends one character unless the preview would exceed its limit.
    fn push_preview(&mut self, c: char) -> bool {
        if self.preview.len().saturating_add(c.len_utf8()) > PREVIEW_BYTES {
            self.preview_full = true;
            return false;
        }
        self.preview.push(c);
        true
    }

    fn sanitizer_encoding(&self) -> EncodingKind {
        self.summary.as_ref().map_or_else(
            || self.sanitizer.detected_encoding().kind,
            |s| s.encoding.kind,
        )
    }
}

impl Drop for FileCore {
    fn drop(&mut self) {
        self.out.zeroize();
        self.preview.zeroize();
    }
}
