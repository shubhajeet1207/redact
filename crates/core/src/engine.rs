//! The streaming sanitizer (TRD §5.1, §5.2): codec → framer → line engine → re-encoder.
//!
//! Fail-closed (invariant I-01): the engine only ever writes sanitized lines. After any error it
//! is poisoned and returns the same error forever; it never falls back to raw input.

use alloc::string::String;
use alloc::vec::Vec;

use crate::census::census;
use crate::codec::{Decoder, Encoder};
use crate::detectors::{Detectors, PemState};
use crate::framer::{Framer, Separator};
use crate::model::{
    CoreError, DetectedEncoding, ErrorCode, Finding, HiddenCensus, InputEncoding, InvalidUtf8,
    Limits, Options, RULE_COUNT, Summary, Warning,
};
use crate::resolve::{Candidate, Edit, Repl, UNION_PLACEHOLDER, resolve_into};
use crate::rules::{self, DetectorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Active,
    Failed(CoreError),
    Finished,
}

/// Streaming sanitizer. Feed any chunking of the input with [`Sanitizer::push`], then call
/// [`Sanitizer::finish`]. Output is identical for every chunking (invariant P-5).
#[derive(Debug)]
pub struct Sanitizer {
    decoder: Decoder,
    framer: Framer,
    engine: LineEngine,
    limits: Limits,
    text: String,
    bytes_in: u64,
    state: State,
}

/// Passes over one line before it is declared unstable and redacted whole (fail closed).
const MAX_PASSES: usize = 4;

#[derive(Debug)]
struct LineEngine {
    options: Options,
    ranges: bool,
    detectors: Detectors,
    pem: PemState,
    /// SR-008 state before the current line; every pass over the line starts from it.
    pem_before: PemState,
    line_no: u64,
    prev_sep: Separator,
    counts: [u64; RULE_COUNT],
    hidden: HiddenCensus,
    findings: Vec<Finding>,
    out_utf8: u64,
    bytes_out: u64,
    encoder: Option<Encoder>,
    max_passes: usize,
    unstable_first: u64,
    unstable_lines: u64,
    cands: Vec<Candidate>,
    edits: Vec<Edit>,
    /// Placeholders inserted into the current line so far, relative to its start.
    line_findings: Vec<Finding>,
    pass_findings: Vec<Finding>,
    merged: Vec<Finding>,
    line_out: String,
    work: String,
}

impl LineEngine {
    fn new(options: Options, ranges: bool, detectors: Detectors) -> Self {
        Self {
            options,
            ranges,
            detectors,
            pem: PemState::default(),
            pem_before: PemState::default(),
            line_no: 0,
            prev_sep: Separator::None,
            counts: [0; RULE_COUNT],
            hidden: HiddenCensus::default(),
            findings: Vec::new(),
            out_utf8: 0,
            bytes_out: 0,
            encoder: None,
            max_passes: MAX_PASSES,
            unstable_first: 0,
            unstable_lines: 0,
            cands: Vec::new(),
            edits: Vec::new(),
            line_findings: Vec::new(),
            pass_findings: Vec::new(),
            merged: Vec::new(),
            line_out: String::new(),
            work: String::new(),
        }
    }

    fn process(&mut self, line: &str, sep: Separator, out: &mut Vec<u8>) -> Result<(), CoreError> {
        let Some(encoder) = self.encoder else {
            // The codec always settles the encoding before producing text.
            return Err(CoreError::new(ErrorCode::InternalError));
        };
        self.line_no = self.line_no.saturating_add(1);
        // Emptying this line would merge the lone CR before it with this LF into one CRLF
        // separator (P-2), so a removed private-key body line keeps its placeholder instead.
        let keep_line =
            self.prev_sep == Separator::Cr && matches!(sep, Separator::Lf | Separator::CrLf);
        self.prev_sep = sep;
        self.sanitize_line(line, keep_line);
        for f in &self.line_findings {
            if let Some(c) = self.counts.get_mut(usize::from(f.rule.0)) {
                *c = c.saturating_add(1);
            }
        }
        if self.ranges {
            let base = self.out_utf8;
            self.findings
                .extend(self.line_findings.iter().map(|f| Finding {
                    start: base.saturating_add(f.start),
                    end: base.saturating_add(f.end),
                    rule: f.rule,
                }));
        }
        census(&self.line_out, &mut self.hidden);
        if sep == Separator::Cr {
            self.hidden.lone_cr = self.hidden.lone_cr.saturating_add(1);
        }
        self.line_out.push_str(sep.as_str());
        self.out_utf8 = self.out_utf8.saturating_add(to_u64(self.line_out.len()));
        let before = out.len();
        encoder.encode(&self.line_out, out);
        self.bytes_out = self
            .bytes_out
            .saturating_add(to_u64(out.len().saturating_sub(before)));
        Ok(())
    }

    /// Sanitizes one line into `line_out` and `line_findings`, repeating until a pass changes
    /// nothing. Running the engine on its own output therefore changes nothing (P-4) by
    /// construction: the final pass is exactly what a second run computes for this line, from
    /// the same SR-008 state. A line still changing after `max_passes` passes is replaced by one
    /// placeholder, which is stable and leaks nothing.
    fn sanitize_line(&mut self, line: &str, keep_line: bool) {
        self.pem_before.copy_from(&self.pem);
        self.line_findings.clear();
        if !self.pass(line, keep_line) {
            return;
        }
        let mut text = core::mem::take(&mut self.work);
        for _ in 1..self.max_passes {
            core::mem::swap(&mut text, &mut self.line_out);
            self.pem.copy_from(&self.pem_before);
            if !self.pass(&text, keep_line) {
                self.work = text;
                return;
            }
        }
        self.work = text;
        self.redact_whole_line();
    }

    /// One detection and resolution pass over `text` into `line_out`. Returns whether the text
    /// changed; only then are this pass's placeholders merged into `line_findings`.
    fn pass(&mut self, text: &str, keep_line: bool) -> bool {
        self.cands.clear();
        self.detectors.run_line(
            text,
            &self.options,
            &mut self.pem,
            self.line_no,
            &mut self.cands,
        );
        if keep_line {
            for c in &mut self.cands {
                if c.repl == Repl::Empty
                    && c.start == 0
                    && usize::try_from(c.end).is_ok_and(|e| e == text.len())
                {
                    c.repl = Repl::Placeholder;
                }
            }
        }
        self.line_out.clear();
        self.pass_findings.clear();
        self.edits.clear();
        resolve_into(
            text,
            &mut self.cands,
            &mut self.line_out,
            &mut self.pass_findings,
            &mut self.edits,
        );
        if self.edits.is_empty() || self.line_out == text {
            return false;
        }
        self.merge_findings();
        true
    }

    /// Moves the earlier passes' placeholders through this pass's edits and merges in the new
    /// ones. A placeholder that an edit overlaps is absorbed into that edit's replacement.
    fn merge_findings(&mut self) {
        self.merged.clear();
        let mut edits = self.edits.iter().peekable();
        let mut fresh = self.pass_findings.iter().copied().peekable();
        let mut delta: i64 = 0;
        for f in &self.line_findings {
            while let Some(e) = edits.next_if(|e| u64::from(e.end) <= f.start) {
                let removed = i64::from(e.end.saturating_sub(e.start));
                delta = delta
                    .saturating_add(i64::from(e.len))
                    .saturating_sub(removed);
            }
            if edits.peek().is_some_and(|e| u64::from(e.start) < f.end) {
                continue;
            }
            let moved = Finding {
                start: f.start.saturating_add_signed(delta),
                end: f.end.saturating_add_signed(delta),
                rule: f.rule,
            };
            while let Some(n) = fresh.next_if(|n| n.start < moved.start) {
                self.merged.push(n);
            }
            self.merged.push(moved);
        }
        self.merged.extend(fresh);
        core::mem::swap(&mut self.merged, &mut self.line_findings);
    }

    /// Fail closed: the whole line becomes `[REDACTED]`, attributed to the highest-precedence
    /// rule that still matched.
    fn redact_whole_line(&mut self) {
        let rule = self
            .cands
            .iter()
            .map(|c| c.rule)
            .min_by_key(|r| rules::rank(*r))
            .unwrap_or(rules::rule_for(DetectorKind::NamedValue));
        self.line_out.clear();
        self.line_out.push_str(UNION_PLACEHOLDER);
        self.line_findings.clear();
        self.line_findings.push(Finding {
            start: 0,
            end: to_u64(UNION_PLACEHOLDER.len()),
            rule,
        });
        if self.unstable_lines == 0 {
            self.unstable_first = self.line_no;
        }
        self.unstable_lines = self.unstable_lines.saturating_add(1);
    }
}

impl Sanitizer {
    /// Creates a sanitizer. `ranges` requests placeholder ranges for highlighting (paste mode).
    pub fn new(
        options: Options,
        limits: Limits,
        encoding: InputEncoding,
        invalid: InvalidUtf8,
        ranges: bool,
    ) -> Result<Self, CoreError> {
        limits.validate()?;
        let detectors = Detectors::new().ok_or(CoreError::new(ErrorCode::InternalError))?;
        Ok(Self {
            decoder: Decoder::new(encoding, invalid),
            framer: Framer::new(limits.max_line_bytes),
            engine: LineEngine::new(options, ranges, detectors),
            limits,
            text: String::new(),
            bytes_in: 0,
            state: State::Active,
        })
    }

    /// Feeds arbitrary bytes and appends complete sanitized lines to `out`. The caller drains
    /// `out` between calls, so memory stays bounded.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CoreError> {
        self.check_active()?;
        self.bytes_in = self.bytes_in.saturating_add(to_u64(input.len()));
        if self
            .limits
            .max_total_bytes
            .is_some_and(|max| self.bytes_in > max)
        {
            return self.fail(CoreError::new(ErrorCode::InputTooLarge));
        }
        self.text.clear();
        let decoded = self.decoder.decode(input, &mut self.text);
        self.ensure_encoder(out);
        if let Err(e) = self.frame(out) {
            return self.fail(e);
        }
        if let Err(e) = decoded {
            return self.fail(CoreError {
                line: Some(self.framer.current_line()),
                ..e
            });
        }
        Ok(())
    }

    /// Flushes the final line and returns the summary. Afterwards the sanitizer accepts no input.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<Summary, CoreError> {
        self.check_active()?;
        self.text.clear();
        let decoded = self.decoder.finish(&mut self.text);
        self.ensure_encoder(out);
        if let Err(e) = self.frame(out) {
            return self.fail(e);
        }
        if let Err(e) = decoded {
            return self.fail(CoreError {
                line: Some(self.framer.current_line()),
                ..e
            });
        }
        let engine = &mut self.engine;
        let flushed = self
            .framer
            .finish(&mut |line, sep| engine.process(line, sep, out));
        if let Err(e) = flushed {
            return self.fail(e);
        }

        let mut warnings = Vec::new();
        if self.engine.pem.in_block {
            warnings.push(Warning::UnterminatedPrivateKeyBlock {
                line: self.engine.pem.start_line,
            });
        }
        if self.engine.unstable_lines > 0 {
            warnings.push(Warning::UnstableLineRedacted {
                first_line: self.engine.unstable_first,
                lines: self.engine.unstable_lines,
            });
        }
        self.state = State::Finished;
        let e = &self.engine;
        Ok(Summary {
            replacements: e.counts.iter().fold(0u64, |a, c| a.saturating_add(*c)),
            by_rule: e.counts,
            lines: self.framer.lines(),
            bytes_in: self.bytes_in,
            bytes_out: e.bytes_out,
            encoding: self.decoder.detected(),
            invalid_utf8_replaced: self.decoder.invalid_replaced(),
            hidden: e.hidden,
            warnings,
            rules_version: rules::RULES_VERSION,
            rules_sha256: rules::RULES_SHA256,
        })
    }

    /// The input encoding detected so far; output uses the same encoding.
    pub fn detected_encoding(&self) -> DetectedEncoding {
        self.decoder.detected()
    }

    /// Zeroes every buffer that held input or output text: the decoded chunk, the framer's
    /// partial line, the codec's pending bytes, and the line buffers. Runs on drop; adapters
    /// may call it earlier (TRD §10.5). Reallocation during growth can leave earlier copies,
    /// which is why this is defence in depth rather than a guarantee (TRD §11.4).
    pub fn wipe(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.text);
        self.framer.wipe();
        self.decoder.wipe();
        zeroize::Zeroize::zeroize(&mut self.engine.line_out);
        zeroize::Zeroize::zeroize(&mut self.engine.work);
    }

    /// Takes the placeholder ranges recorded so far (UTF-8 byte offsets into the sanitized text,
    /// excluding any byte-order mark). Empty unless `ranges` was requested.
    pub fn take_ranges(&mut self) -> Vec<Finding> {
        core::mem::take(&mut self.engine.findings)
    }

    fn frame(&mut self, out: &mut Vec<u8>) -> Result<(), CoreError> {
        let engine = &mut self.engine;
        self.framer
            .push(&self.text, &mut |line, sep| engine.process(line, sep, out))
    }

    /// Writes the BOM, if any, once the input encoding is known.
    fn ensure_encoder(&mut self, out: &mut Vec<u8>) {
        if self.engine.encoder.is_none() && self.decoder.is_detected() {
            let encoder = Encoder::new(self.decoder.detected());
            out.extend_from_slice(encoder.bom());
            self.engine.bytes_out = self
                .engine
                .bytes_out
                .saturating_add(to_u64(encoder.bom().len()));
            self.engine.encoder = Some(encoder);
        }
    }

    fn check_active(&self) -> Result<(), CoreError> {
        match self.state {
            State::Active => Ok(()),
            State::Failed(e) => Err(e),
            State::Finished => Err(CoreError::new(ErrorCode::InvalidOptions)),
        }
    }

    fn fail<T>(&mut self, e: CoreError) -> Result<T, CoreError> {
        self.state = State::Failed(e);
        Err(e)
    }
}

impl Drop for Sanitizer {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Sanitizes a complete buffer. Convenience wrapper over [`Sanitizer`].
pub fn sanitize_bytes(
    input: &[u8],
    options: Options,
    limits: Limits,
    ranges: bool,
) -> Result<(Vec<u8>, Summary, Vec<Finding>), CoreError> {
    let mut s = Sanitizer::new(
        options,
        limits,
        InputEncoding::Auto,
        InvalidUtf8::Error,
        ranges,
    )?;
    let mut out = Vec::with_capacity(input.len());
    s.push(input, &mut out)?;
    let summary = s.finish(&mut out)?;
    Ok((out, summary, s.take_ranges()))
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::panic)] // Test failures panic by design.
mod tests {
    extern crate std;

    use super::*;

    fn sanitize(input: &str, passes: usize) -> (String, Summary, Vec<Finding>) {
        let mut s = Sanitizer::new(
            Options::default(),
            Limits::default(),
            InputEncoding::Auto,
            InvalidUtf8::Error,
            true,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        s.engine.max_passes = passes;
        let mut out = Vec::new();
        s.push(input.as_bytes(), &mut out)
            .unwrap_or_else(|e| panic!("{e}"));
        let summary = s.finish(&mut out).unwrap_or_else(|e| panic!("{e}"));
        let text = String::from_utf8(out).unwrap_or_default();
        (text, summary, s.take_ranges())
    }

    /// Findings point at placeholders in order, and counts equal findings (P-6).
    fn assert_consistent(out: &str, summary: &Summary, findings: &[Finding]) {
        assert_eq!(summary.replacements, to_u64(findings.len()));
        assert_eq!(summary.by_rule.iter().sum::<u64>(), summary.replacements);
        let mut last = 0u64;
        for f in findings {
            assert!(f.start >= last && f.end > f.start, "{findings:?}");
            let text = usize::try_from(f.start)
                .ok()
                .zip(usize::try_from(f.end).ok())
                .and_then(|(s, e)| out.get(s..e))
                .unwrap_or_default();
            assert!(rules::PLACEHOLDERS.contains(&text), "{text:?} in {out:?}");
            last = f.end;
        }
    }

    #[test]
    fn wipe_clears_every_buffer_that_held_input() {
        let mut s = Sanitizer::new(
            Options::default(),
            Limits::default(),
            InputEncoding::Auto,
            InvalidUtf8::Error,
            false,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let mut out = Vec::new();
        s.push(
            b"password=fake-one
partial line token=fake-two",
            &mut out,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(s.framer.carry_len() > 0);
        s.wipe();
        assert!(s.text.is_empty() && s.engine.line_out.is_empty() && s.engine.work.is_empty());
        assert_eq!(s.framer.carry_len(), 0);
        assert_eq!(s.decoder.pending_len(), 0);
    }

    #[test]
    fn line_still_changing_after_max_passes_is_redacted_whole() {
        let (out, summary, findings) = sanitize(
            "a password=x b
next=1
",
            1,
        );
        assert_eq!(
            out,
            "[REDACTED]
next=1
"
        );
        assert_eq!(
            summary.warnings,
            [Warning::UnstableLineRedacted {
                first_line: 1,
                lines: 1
            }]
        );
        assert_eq!(summary.by_rule.get(rules::IDX_NAMED_VALUE), Some(&1));
        assert_eq!(
            summary.warnings.first().map(Warning::code),
            Some("UNSTABLE_LINE_REDACTED")
        );
        assert_eq!(
            findings,
            [Finding {
                start: 0,
                end: 10,
                rule: rules::rule_for(DetectorKind::NamedValue)
            }]
        );
        assert_consistent(&out, &summary, &findings);
    }

    #[test]
    fn line_needing_several_passes_converges_and_keeps_findings_aligned() {
        for input in [
            "Cookie: a=DB_PASSWORD=';' x@example.com",
            // The second pass shortens text before the email placeholder from the first pass.
            "Cookie: a=DB_PASSWORD=';'; x@example.com",
            "Cookie: a=Authorization: Bearer \"api_key\": \";\"api_key\": \"password=",
        ] {
            let (once, summary, findings) = sanitize(input, MAX_PASSES);
            assert!(
                summary.warnings.is_empty(),
                "{input:?}: {:?}",
                summary.warnings
            );
            assert_consistent(&once, &summary, &findings);
            let (twice, again, _) = sanitize(&once, MAX_PASSES);
            assert_eq!(twice, once, "{input:?}");
            assert_eq!(again.replacements, 0, "{input:?}");
        }
    }
}
