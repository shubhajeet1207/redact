//! Byte-level scanning helpers shared by the detectors. Every helper is bounds-checked; none can
//! panic on any input.
#![allow(clippy::arithmetic_side_effects)] // Positions are bounded by the line length (≤ 64 MiB).

use alloc::vec::Vec;

use crate::model::RuleId;
use crate::resolve::{Candidate, Repl};

/// Characters of a key token: ASCII letters, digits, `_`, `-`, `.` (TRD §6.1).
#[inline]
pub(crate) fn is_key_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')
}

/// Space or tab.
#[inline]
pub(crate) fn is_space(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// The byte at `i`, if any.
#[inline]
pub(crate) fn at(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}

/// The byte before `i`, if any.
#[inline]
pub(crate) fn before(b: &[u8], i: usize) -> Option<u8> {
    i.checked_sub(1).and_then(|j| at(b, j))
}

/// First position at or after `from` (and before `end`) where `pred` is false.
#[inline]
pub(crate) fn skip_while(b: &[u8], from: usize, end: usize, pred: impl Fn(u8) -> bool) -> usize {
    let end = end.min(b.len());
    let mut i = from.min(end);
    while i < end && b.get(i).is_some_and(|c| pred(*c)) {
        i += 1;
    }
    i
}

/// First position at or after `from` (and before `end`) where `pred` is true, or `end`.
#[inline]
pub(crate) fn find_from(b: &[u8], from: usize, end: usize, pred: impl Fn(u8) -> bool) -> usize {
    skip_while(b, from, end, |c| !pred(c))
}

/// ASCII case-insensitive equality.
#[inline]
pub(crate) fn eq_ic(a: &[u8], b: &str) -> bool {
    a.eq_ignore_ascii_case(b.as_bytes())
}

/// ASCII case-insensitive prefix test.
#[inline]
pub(crate) fn starts_with_ic(hay: &[u8], needle: &str) -> bool {
    hay.get(..needle.len()).is_some_and(|h| eq_ic(h, needle))
}

/// `b[s..e]`, or empty when out of range.
#[inline]
pub(crate) fn slice(b: &[u8], s: usize, e: usize) -> &[u8] {
    b.get(s..e).unwrap_or_default()
}

/// Pushes a placeholder candidate for `b[s..e]` when non-empty.
#[inline]
pub(crate) fn push(out: &mut Vec<Candidate>, s: usize, e: usize, rule: RuleId) {
    push_repl(out, s, e, rule, Repl::Placeholder);
}

#[inline]
pub(crate) fn push_repl(out: &mut Vec<Candidate>, s: usize, e: usize, rule: RuleId, repl: Repl) {
    if s < e
        && let (Ok(start), Ok(end)) = (u32::try_from(s), u32::try_from(e))
    {
        out.push(Candidate {
            start,
            end,
            rule,
            repl,
        });
    }
}
