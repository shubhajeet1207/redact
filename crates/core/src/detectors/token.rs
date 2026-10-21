//! SR-007 known credential formats (TRD §6.8). One Aho–Corasick pass finds every documented
//! prefix; each hit is checked against its format's segment grammar.
#![allow(clippy::arithmetic_side_effects)] // Positions are bounded by the line length (≤ 64 MiB).

use alloc::vec::Vec;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::model::RuleId;
use crate::resolve::Candidate;
use crate::rules::{self, Segment, TokenFormat};
use crate::scan::{at, before, push};

/// Prefix automaton built once per sanitizer from the compiled format table.
#[derive(Debug)]
pub(crate) struct TokenMatcher {
    ac: AhoCorasick,
    /// Format index for each automaton pattern.
    format_of: Vec<usize>,
}

impl TokenMatcher {
    pub(crate) fn new() -> Option<Self> {
        let mut patterns = Vec::new();
        let mut format_of = Vec::new();
        for (fi, f) in rules::TOKEN_FORMATS.iter().enumerate() {
            for p in f.prefixes {
                patterns.push(*p);
                format_of.push(fi);
            }
        }
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .ok()?;
        Some(Self { ac, format_of })
    }
}

/// Characters that may not precede a prefix: a prefix inside a longer token is not a match.
fn is_boundary_blocker(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')
}

pub(crate) fn detect(m: &TokenMatcher, b: &[u8], rule: RuleId, out: &mut Vec<Candidate>) {
    let mut covered = 0;
    for hit in m.ac.find_iter(b) {
        let s = hit.start();
        if s < covered || before(b, s).is_some_and(is_boundary_blocker) {
            continue;
        }
        let Some(format) = m
            .format_of
            .get(hit.pattern().as_usize())
            .and_then(|i| rules::TOKEN_FORMATS.get(*i))
        else {
            continue;
        };
        if let Some(end) = body_end(b, hit.end(), format) {
            push(out, s, end, rule);
            covered = end;
        }
    }
}

/// End of the body after the prefix, when it matches the format's `.`-separated segments.
/// Exact segments must have exactly `min` characters; others take the whole run (≥ `min`).
fn body_end(b: &[u8], mut pos: usize, format: &TokenFormat) -> Option<usize> {
    for (k, seg) in format.segments.iter().enumerate() {
        if k > 0 {
            if at(b, pos) != Some(b'.') {
                return None;
            }
            pos += 1;
        }
        let s = pos;
        while at(b, pos).is_some_and(|c| seg.charset.contains(c)) {
            pos += 1;
        }
        if !length_ok(seg, pos - s) {
            return None;
        }
    }
    // An exact-length body must end at a token boundary (TRD §6.8); `.` may follow (sentence
    // punctuation, further JWE segments).
    let exact_tail = format.segments.last().is_some_and(|s| s.exact);
    if exact_tail && at(b, pos).is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return None;
    }
    Some(pos)
}

fn length_ok(seg: &Segment, n: usize) -> bool {
    let min = usize::try_from(seg.min).unwrap_or(usize::MAX);
    if seg.exact { n == min } else { n >= min }
}
