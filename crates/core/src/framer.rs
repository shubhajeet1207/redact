//! Line framing (TRD §5.2). Splits decoded text into lines on LF, CRLF, and lone CR, holding a
//! CR at a chunk end until the next character decides it. Separators are passed through
//! verbatim. The carry buffer is bounded by `max_line_bytes`, so memory never depends on input
//! size.

use alloc::string::String;

use crate::model::{CoreError, ErrorCode};

/// A line separator, emitted unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separator {
    /// The final line has no separator.
    None,
    Lf,
    CrLf,
    /// A lone carriage return.
    Cr,
}

impl Separator {
    pub fn as_str(self) -> &'static str {
        match self {
            Separator::None => "",
            Separator::Lf => "\n",
            Separator::CrLf => "\r\n",
            Separator::Cr => "\r",
        }
    }
}

/// Receives each complete line and its separator.
pub type LineSink<'a> = dyn FnMut(&str, Separator) -> Result<(), CoreError> + 'a;

#[derive(Debug)]
pub struct Framer {
    max_line_bytes: usize,
    carry: String,
    pending_cr: bool,
    lines: u64,
}

impl Framer {
    pub fn new(max_line_bytes: u32) -> Self {
        Self {
            max_line_bytes: usize::try_from(max_line_bytes).unwrap_or(usize::MAX),
            carry: String::new(),
            pending_cr: false,
            lines: 0,
        }
    }

    /// Bytes of the line currently being assembled.
    pub fn carry_len(&self) -> usize {
        self.carry.len()
    }

    /// Zeroes the partial line before releasing it (TRD §10.5, §11.4).
    pub fn wipe(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.carry);
    }

    /// Completed lines so far.
    pub fn lines(&self) -> u64 {
        self.lines
    }

    /// The 1-based number of the line currently being assembled.
    pub fn current_line(&self) -> u64 {
        self.lines.saturating_add(1)
    }

    pub fn push(&mut self, text: &str, sink: &mut LineSink<'_>) -> Result<(), CoreError> {
        let mut rest = text;
        if self.pending_cr && !rest.is_empty() {
            self.pending_cr = false;
            if let Some(after) = rest.strip_prefix('\n') {
                self.emit("", Separator::CrLf, sink)?;
                rest = after;
            } else {
                self.emit("", Separator::Cr, sink)?;
            }
        }
        while let Some(i) = memchr::memchr2(b'\n', b'\r', rest.as_bytes()) {
            let (line, from_sep) = rest.split_at(i);
            if let Some(after) = from_sep.strip_prefix("\r\n") {
                self.emit(line, Separator::CrLf, sink)?;
                rest = after;
            } else if let Some(after) = from_sep.strip_prefix('\n') {
                self.emit(line, Separator::Lf, sink)?;
                rest = after;
            } else if from_sep == "\r" {
                // A CR at the chunk end may be the first half of a CRLF.
                self.append(line)?;
                self.pending_cr = true;
                return Ok(());
            } else {
                let after = from_sep.get(1..).unwrap_or_default();
                self.emit(line, Separator::Cr, sink)?;
                rest = after;
            }
        }
        self.append(rest)
    }

    /// Flushes a held CR and the final unterminated line.
    pub fn finish(&mut self, sink: &mut LineSink<'_>) -> Result<(), CoreError> {
        if self.pending_cr {
            self.pending_cr = false;
            self.emit("", Separator::Cr, sink)?;
        } else if !self.carry.is_empty() {
            self.emit("", Separator::None, sink)?;
        }
        Ok(())
    }

    fn append(&mut self, part: &str) -> Result<(), CoreError> {
        self.check(self.carry.len().saturating_add(part.len()))?;
        self.carry.push_str(part);
        Ok(())
    }

    fn emit(
        &mut self,
        part: &str,
        sep: Separator,
        sink: &mut LineSink<'_>,
    ) -> Result<(), CoreError> {
        self.check(self.carry.len().saturating_add(part.len()))?;
        if self.carry.is_empty() {
            sink(part, sep)?;
        } else {
            self.carry.push_str(part);
            let line = core::mem::take(&mut self.carry);
            sink(&line, sep)?;
            // Reuse the allocation for the next line.
            self.carry = line;
            self.carry.clear();
        }
        self.lines = self.lines.saturating_add(1);
        Ok(())
    }

    fn check(&self, len: usize) -> Result<(), CoreError> {
        if len > self.max_line_bytes {
            Err(CoreError::at(ErrorCode::LineTooLong, self.current_line()))
        } else {
            Ok(())
        }
    }
}
