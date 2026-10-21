//! SR-005 email addresses (TRD §6.6): a pragmatic ASCII grammar with bounded scans around each
//! `@`. Inside a URL authority only the username part may match (TRD §6.4).
#![allow(clippy::arithmetic_side_effects)] // Positions are bounded by the line length (≤ 64 MiB).

use alloc::vec::Vec;

use super::url::{UrlSpan, authority_overlapping, overlaps_scheme};
use crate::model::RuleId;
use crate::resolve::Candidate;
use crate::scan::{at, before, push, slice};

const MAX_LOCAL: usize = 64;
const MAX_DOMAIN: usize = 253;

fn is_local_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')
}

pub(crate) fn detect(b: &[u8], spans: &[UrlSpan], rule: RuleId, out: &mut Vec<Candidate>) {
    let mut resume = 0;
    for a in memchr::memchr_iter(b'@', b) {
        if a < resume {
            continue;
        }
        if let Some((s, e)) = email_at(b, a) {
            let allowed = match authority_overlapping(spans, s, e) {
                None => true,
                Some(sp) => sp
                    .user_end()
                    .is_some_and(|ue| s >= sp.auth_start && e <= ue),
            };
            if allowed && !overlaps_scheme(spans, s, e) {
                push(out, s, e, rule);
                resume = e;
            }
        }
    }
}

/// The email address whose `@` is at `a`, if the surrounding text matches the grammar.
fn email_at(b: &[u8], a: usize) -> Option<(usize, usize)> {
    let mut s = a;
    while before(b, s).is_some_and(is_local_char) {
        s -= 1;
        if a - s > MAX_LOCAL {
            return None;
        }
    }
    let local = slice(b, s, a);
    if local.is_empty()
        || before(b, s) == Some(b'@')
        || local.first() == Some(&b'.')
        || local.last() == Some(&b'.')
        || local.windows(2).any(|w| w == b"..")
    {
        return None;
    }

    let ds = a + 1;
    let mut e = ds;
    while at(b, e).is_some_and(is_domain_char) {
        e += 1;
        if e - ds > MAX_DOMAIN + 1 {
            return None;
        }
    }
    // Trailing dots are sentence punctuation, not part of the domain.
    while e > ds && before(b, e) == Some(b'.') {
        e -= 1;
    }
    if at(b, e).is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'@')) {
        return None;
    }
    let domain = slice(b, ds, e);
    if domain.is_empty() || domain.len() > MAX_DOMAIN || !valid_domain(domain) {
        return None;
    }
    Some((s, e))
}

fn valid_domain(d: &[u8]) -> bool {
    let mut labels = 0usize;
    let mut last: &[u8] = &[];
    for label in d.split(|c| *c == b'.') {
        let ok = (1..=63).contains(&label.len())
            && label.first() != Some(&b'-')
            && label.last() != Some(&b'-')
            && label
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-');
        if !ok {
            return false;
        }
        labels += 1;
        last = label;
    }
    labels >= 2 && (2..=63).contains(&last.len()) && last.iter().all(u8::is_ascii_alphabetic)
}
