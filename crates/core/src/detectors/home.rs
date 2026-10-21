//! SR-004 usernames in home-directory paths (TRD §6.5).
#![allow(clippy::arithmetic_side_effects)] // Positions are bounded by the line length (≤ 64 MiB).

use alloc::vec::Vec;

use super::Finders;
use super::url::{UrlSpan, containing, overlaps_scheme};
use crate::model::RuleId;
use crate::resolve::Candidate;
use crate::rules;
use crate::scan::{at, before, push, slice, starts_with_ic};

const MAX_USER: usize = 64;
const MAX_QUOTED_USER: usize = 256;
const MAX_PATH_LOOKBACK: usize = 1024;

/// The previous look-behind result `(position, quote)`. Look-behind that reaches the previous
/// position reuses its answer, so no byte is scanned twice (linear time).
type QuoteCache = Option<(usize, Option<u8>)>;

pub(crate) fn detect(
    finders: &Finders,
    b: &[u8],
    spans: &[UrlSpan],
    rule: RuleId,
    out: &mut Vec<Candidate>,
) {
    for (prefix, finder) in rules::HOME_POSIX_PREFIXES.iter().zip(&finders.home) {
        let mut cache: QuoteCache = None;
        for p in finder.find_iter(b) {
            if in_non_file_url(spans, p) {
                continue;
            }
            let quote = path_quote(b, p, &mut cache);
            username(b, p + prefix.len(), quote, |c| c == b'/', spans, rule, out);
        }
    }
    let mut cache: QuoteCache = None;
    for c in memchr::memchr_iter(b':', b) {
        let Some(d) = c.checked_sub(1) else { continue };
        if !at(b, d).is_some_and(|x| x.is_ascii_alphabetic())
            || before(b, d).is_some_and(|x| x.is_ascii_alphanumeric() || x == b'_')
        {
            continue;
        }
        let sep: &[u8] = match (at(b, c + 1), at(b, c + 2)) {
            (Some(b'\\'), Some(b'\\')) => b"\\\\",
            (Some(b'\\'), _) => b"\\",
            (Some(b'/'), _) => b"/",
            _ => continue,
        };
        let dir = c + 1 + sep.len();
        let after_dir = dir + rules::HOME_WINDOWS_DIR.len();
        if !starts_with_ic(slice(b, dir, b.len()), rules::HOME_WINDOWS_DIR)
            || !slice(b, after_dir, b.len()).starts_with(sep)
            || in_non_file_url(spans, d)
        {
            continue;
        }
        let quote = path_quote(b, d, &mut cache);
        username(
            b,
            after_dir + sep.len(),
            quote,
            |x| x == b'\\' || x == b'/',
            spans,
            rule,
            out,
        );
    }
}

fn in_non_file_url(spans: &[UrlSpan], p: usize) -> bool {
    containing(spans, p).is_some_and(|s| !s.file_scheme)
}

/// The quote enclosing the path that contains position `p`, found by scanning back to the
/// start of the path (no whitespace or quotes), at most 1 KiB.
fn path_quote(b: &[u8], p: usize, cache: &mut QuoteCache) -> Option<u8> {
    let floor = p.saturating_sub(MAX_PATH_LOOKBACK);
    let mut j = p;
    let quote = loop {
        if let Some((pos, q)) = *cache
            && j == pos
        {
            break q;
        }
        match before(b, j) {
            Some(q @ (b'"' | b'\'')) => break Some(q),
            Some(c) if c.is_ascii_whitespace() => break None,
            Some(_) if j > floor => j -= 1,
            _ => break None,
        }
    };
    *cache = Some((p, quote));
    quote
}

/// Redacts the username starting at `us` when it matches the grammar and is followed by a
/// separator or a path terminator.
fn username(
    b: &[u8],
    us: usize,
    quote: Option<u8>,
    is_sep: impl Fn(u8) -> bool,
    spans: &[UrlSpan],
    rule: RuleId,
    out: &mut Vec<Candidate>,
) {
    let mut emit = |s: usize, e: usize| {
        if !overlaps_scheme(spans, s, e) {
            push(out, s, e, rule);
        }
    };
    match quote {
        None => {
            let mut e = us;
            while at(b, e)
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
            {
                e += 1;
                if e - us > MAX_USER {
                    return;
                }
            }
            let user = slice(b, us, e);
            let terminated = at(b, e).is_none_or(|c| {
                is_sep(c)
                    || c.is_ascii_whitespace()
                    || matches!(c, b'"' | b'\'' | b':' | b';' | b',' | b')' | b']' | b'}')
            });
            if !user.is_empty() && terminated && user.iter().any(u8::is_ascii_alphabetic) {
                emit(us, e);
            }
        }
        Some(q) => {
            let mut e = us;
            while let Some(c) = at(b, e) {
                if quoted_path_terminator(c, q) || c < 0x20 || c == 0x7F {
                    break;
                }
                e += 1;
                if e - us > MAX_QUOTED_USER {
                    return;
                }
            }
            let user = slice(b, us, e);
            let terminated = at(b, e).is_some_and(|c| quoted_path_terminator(c, q));
            let meaningful = user.iter().any(|c| !c.is_ascii_digit() && *c != b' ');
            if !user.is_empty() && terminated && meaningful {
                emit(us, e);
            }
        }
    }
}

/// A quoted path's username may contain spaces and Unicode; it ends at a separator or the
/// closing quote (TRD §6.5).
fn quoted_path_terminator(c: u8, quote: u8) -> bool {
    matches!(c, b'/' | b'\\') || c == quote
}
