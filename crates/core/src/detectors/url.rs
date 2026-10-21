//! URL structure and SR-003 URL credentials (TRD §6.4). URL spans are computed first because
//! SR-004 and SR-005 need them for disambiguation.
#![allow(clippy::arithmetic_side_effects)] // Positions are bounded by the line length (≤ 64 MiB).

use alloc::vec::Vec;

use super::Finders;
use crate::model::RuleId;
use crate::resolve::Candidate;
use crate::scan::{at, before, eq_ic, find_from, push, slice};

const MAX_SCHEME: usize = 32;

/// A recognized `scheme://` URL in a line. Positions are byte offsets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UrlSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) auth_start: usize,
    pub(crate) auth_end: usize,
    /// Last `@` in the authority (user-information delimiter).
    pub(crate) at: Option<usize>,
    /// First `:` in the user information (password delimiter).
    pub(crate) colon: Option<usize>,
    pub(crate) file_scheme: bool,
}

impl UrlSpan {
    /// End of the username part of the user information, when there is user information.
    pub(crate) fn user_end(&self) -> Option<usize> {
        self.at.map(|a| self.colon.unwrap_or(a))
    }
}

fn is_scheme_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-')
}

fn is_url_end(c: u8) -> bool {
    c.is_ascii_whitespace()
        || c.is_ascii_control()
        || matches!(c, b'"' | b'\'' | b'<' | b'>' | b'`')
}

/// A URL authority starts with a hostname/user-information character or an IPv6 opening bracket.
/// An initial `:` is also valid for an empty username followed by a password (for example,
/// `redis://:password@host`). Rejecting malformed `scheme://,` forms prevents them from
/// suppressing unrelated path and email rules that would remain after another detector redacts
/// the apparent scheme.
fn valid_authority_start(b: &[u8], start: usize, end: usize) -> bool {
    match at(b, start) {
        Some(c) if c.is_ascii_alphanumeric() || c == b'[' => true,
        Some(b':') => {
            let mut position = start.saturating_add(1);
            while position < end {
                let Some(byte) = at(b, position) else {
                    return false;
                };
                if byte == b'@' {
                    return true;
                }
                if matches!(byte, b'/' | b'?' | b'#') || is_url_end(byte) {
                    return false;
                }
                position = position.saturating_add(1);
            }
            false
        }
        _ => false,
    }
}

/// Every `scheme://` URL in the line, in order. Linear: the URL end is cached across
/// overlapping candidates and each authority ends before the next `://`.
pub(crate) fn spans(finders: &Finders, b: &[u8], out: &mut Vec<UrlSpan>) {
    out.clear();
    let len = b.len();
    let mut cached_end: Option<usize> = None;
    for idx in finders.scheme.find_iter(b) {
        let mut ss = idx;
        while ss > 0 && idx - ss <= MAX_SCHEME && before(b, ss).is_some_and(is_scheme_char) {
            ss -= 1;
        }
        let scheme = slice(b, ss, idx);
        if scheme.is_empty()
            || scheme.len() > MAX_SCHEME
            || before(b, ss).is_some_and(is_scheme_char)
            || !at(b, ss).is_some_and(|c| c.is_ascii_alphabetic())
        {
            continue;
        }
        let auth_start = idx + 3;
        if !valid_authority_start(b, auth_start, len) {
            continue;
        }
        let end = match cached_end {
            Some(e) if e >= auth_start => e,
            _ => find_from(b, auth_start, len, is_url_end),
        };
        cached_end = Some(end);
        let auth_end = find_from(b, auth_start, end, |c| matches!(c, b'/' | b'?' | b'#'));
        let authority = slice(b, auth_start, auth_end);
        let at_pos = memchr::memrchr(b'@', authority).map(|r| auth_start + r);
        let colon = at_pos
            .and_then(|a| memchr::memchr(b':', slice(b, auth_start, a)).map(|r| auth_start + r));
        out.push(UrlSpan {
            start: ss,
            end,
            auth_start,
            auth_end,
            at: at_pos,
            colon,
            file_scheme: eq_ic(scheme, "file"),
        });
    }
}

/// SR-003: the non-empty password between the first `:` of the user information and the last
/// `@` of the authority.
pub(crate) fn detect(spans: &[UrlSpan], rule: RuleId, out: &mut Vec<Candidate>) {
    for s in spans {
        if let (Some(c), Some(a)) = (s.colon, s.at) {
            push(out, c + 1, a, rule);
        }
    }
}

/// The span whose `[start, end)` contains `pos`, if any (spans are ordered by start).
pub(crate) fn containing(spans: &[UrlSpan], pos: usize) -> Option<&UrlSpan> {
    let idx = spans.partition_point(|s| s.start <= pos);
    idx.checked_sub(1)
        .and_then(|i| spans.get(i))
        .filter(|s| pos < s.end)
}

/// True when `[s, e)` overlaps some URL's `scheme://` prefix. Redacting there would destroy the
/// URL and change how a second run reads the line (invariant P-4).
pub(crate) fn overlaps_scheme(spans: &[UrlSpan], s: usize, e: usize) -> bool {
    let idx = spans.partition_point(|sp| sp.start < e);
    idx.checked_sub(1)
        .and_then(|i| spans.get(i))
        .is_some_and(|sp| s < sp.auth_start)
}

/// The span whose authority overlaps `[s, e)`, if any.
pub(crate) fn authority_overlapping(spans: &[UrlSpan], s: usize, e: usize) -> Option<&UrlSpan> {
    let idx = spans.partition_point(|sp| sp.auth_start < e);
    let lo = idx.saturating_sub(2);
    spans
        .get(lo..idx)
        .unwrap_or_default()
        .iter()
        .rev()
        .find(|sp| s < sp.auth_end && e > sp.auth_start)
}
