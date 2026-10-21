//! Assignment-shaped secrets (TRD §6.2, §6.3, §6.10): SR-001 named values, SR-002 authorization
//! credentials, and SR-009 cookie values. One left-to-right pass over `=`/`:` separators finds
//! keys by bounded look-behind; a second pass handles space-separated command-line flags.
#![allow(clippy::arithmetic_side_effects)] // Positions are bounded by the line length (≤ 64 MiB).

use alloc::vec::Vec;

use crate::resolve::Candidate;
use crate::rules::{self, DetectorKind};
use crate::scan::{at, before, eq_ic, find_from, is_key_char, is_space, push, skip_while, slice};

const MAX_KEY: usize = 128;
const MAX_SPACE_BEFORE_SEP: usize = 16;

#[derive(Clone, Copy)]
enum KeyKind {
    Secret,
    Authorization,
    CookieRequest,
    CookieResponse,
}

pub(crate) fn detect(b: &[u8], out: &mut Vec<Candidate>) {
    scan_separators(b, out);
    scan_flags(b, out);
}

fn scan_separators(b: &[u8], out: &mut Vec<Candidate>) {
    let len = b.len();
    let mut i = 0;
    // Header fields never hide their contents from scanning (other headers may share the line);
    // overlap resolution merges duplicates. These marks keep repeated headers linear: a header
    // whose value lies inside text already covered by the same kind is not parsed again.
    let (mut auth_covered, mut cookie_covered) = (0usize, 0usize);
    while let Some(rel) = memchr::memchr2(b'=', b':', slice(b, i, len)) {
        let s = i + rel;
        let (sep_end, valid) = separator(b, s);
        i = sep_end;
        if !valid {
            continue;
        }
        let Some((ks, ke)) = key_before(b, s) else {
            continue;
        };
        let Some(kind) = classify(slice(b, ks, ke)) else {
            continue;
        };
        let v = skip_while(b, sep_end, len, is_space);
        match kind {
            // A redacted secret value hides nothing: skip past it (keeps `a=a=a=…` linear).
            KeyKind::Secret => i = secret_value(b, v, out).max(sep_end),
            KeyKind::Authorization if v >= auth_covered => {
                auth_covered = authorization_value(b, v, out)
            }
            KeyKind::CookieRequest | KeyKind::CookieResponse if v >= cookie_covered => {
                cookie_covered = cookie_value(b, v, matches!(kind, KeyKind::CookieResponse), out);
            }
            _ => {}
        }
    }
}

/// Classifies the separator at `s` (`=` or `:`): returns its end and whether it assigns.
fn separator(b: &[u8], s: usize) -> (usize, bool) {
    match at(b, s) {
        Some(b':') => match (at(b, s + 1), at(b, s + 2)) {
            (Some(b'='), _) => (s + 2, true),
            (Some(b':'), _) => (s + 2, false),
            (Some(b'/'), Some(b'/')) => (s + 3, false),
            _ => (s + 1, before(b, s) != Some(b':')),
        },
        Some(b'=') => match (before(b, s), at(b, s + 1)) {
            (Some(b'=' | b'!' | b'<' | b'>' | b':'), _) => (s + 1, false),
            (_, Some(b'=')) => (s + 2, false),
            (_, Some(b'>')) => (s + 2, true),
            _ => (s + 1, true),
        },
        _ => (s + 1, false),
    }
}

/// Finds the key ending just before the separator at `s` (TRD §6.2 key forms).
fn key_before(b: &[u8], s: usize) -> Option<(usize, usize)> {
    let mut j = s;
    let mut spaces = 0;
    loop {
        if spaces < MAX_SPACE_BEFORE_SEP && before(b, j).is_some_and(is_space) {
            j -= 1;
            spaces += 1;
        } else if let Some(esc) = csi_ending_at(b, j) {
            // A terminal color code between key and separator (`KEY[0m=`).
            j = esc;
        } else {
            break;
        }
    }
    let quote = match before(b, j) {
        Some(q @ (b'"' | b'\'')) => {
            j -= 1;
            Some(q)
        }
        _ => None,
    };
    let ke = j;
    let mut ks = j;
    while before(b, ks).is_some_and(is_key_char) {
        ks -= 1;
        if ke - ks > MAX_KEY {
            return None;
        }
    }
    let ks = strip_glued_csi(b, ks, ke);
    if ks == ke || !slice(b, ks, ke).iter().any(u8::is_ascii_alphabetic) {
        return None;
    }
    if let Some(q) = quote
        && before(b, ks) != Some(q)
    {
        return None;
    }
    Some((ks, ke))
}

/// When `b[..end]` ends with a terminal CSI sequence (`ESC [ params final`), its start.
fn csi_ending_at(b: &[u8], end: usize) -> Option<usize> {
    let fin = end.checked_sub(1)?;
    if !at(b, fin)?.is_ascii_alphabetic() {
        return None;
    }
    let mut r = fin;
    while before(b, r).is_some_and(|c| c.is_ascii_digit() || c == b';') {
        r -= 1;
    }
    (before(b, r) == Some(b'[') && before(b, r - 1) == Some(0x1B)).then(|| r - 2)
}

/// A key run can start with the tail of a color code glued to it (`ESC[31mtoken`): the run
/// begins with the code's digits and final letter. Returns the key start without them.
fn strip_glued_csi(b: &[u8], ks: usize, ke: usize) -> usize {
    let mut r = ks;
    while before(b, r).is_some_and(|c| c.is_ascii_digit() || c == b';') {
        r -= 1;
    }
    if before(b, r) != Some(b'[') || before(b, r - 1) != Some(0x1B) {
        return ks;
    }
    let digits_end = skip_while(b, ks, ke, |c| c.is_ascii_digit());
    if digits_end < ke && at(b, digits_end).is_some_and(|c| c.is_ascii_alphabetic()) {
        digits_end + 1
    } else {
        ks
    }
}

fn classify(key: &[u8]) -> Option<KeyKind> {
    if rules::AUTH_HEADERS.iter().any(|h| eq_ic(key, h)) {
        Some(KeyKind::Authorization)
    } else if rules::COOKIE_REQUEST_HEADERS.iter().any(|h| eq_ic(key, h)) {
        Some(KeyKind::CookieRequest)
    } else if rules::COOKIE_RESPONSE_HEADERS.iter().any(|h| eq_ic(key, h)) {
        Some(KeyKind::CookieResponse)
    } else if is_secret_key(key) {
        Some(KeyKind::Secret)
    } else {
        None
    }
}

/// True when the key's final segment, or final two segments, name a secret (TRD §6.2).
fn is_secret_key(key: &[u8]) -> bool {
    let (prev, last) = last_two_segments(key);
    let Some(last) = last else { return false };
    if rules::SECRET_SINGLE_ALIASES.iter().any(|a| eq_ic(last, a)) {
        return true;
    }
    prev.is_some_and(|p| {
        rules::SECRET_PAIR_ALIASES
            .iter()
            .any(|(a, z)| eq_ic(p, a) && eq_ic(last, z))
    })
}

/// Splits a key at `_`, `-`, `.` and camel-case transitions; returns the last two segments.
fn last_two_segments(key: &[u8]) -> (Option<&[u8]>, Option<&[u8]>) {
    let mut prev: Option<(usize, usize)> = None;
    let mut last: Option<(usize, usize)> = None;
    let mut start: Option<usize> = None;
    let mut close = |s: usize, e: usize| {
        prev = last;
        last = Some((s, e));
    };
    for (i, &c) in key.iter().enumerate() {
        if matches!(c, b'_' | b'-' | b'.') {
            if let Some(s) = start.take() {
                close(s, i);
            }
            continue;
        }
        match start {
            None => start = Some(i),
            Some(s) => {
                let p = before(key, i).unwrap_or(0);
                let next_lower = at(key, i + 1).is_some_and(|n| n.is_ascii_lowercase());
                let boundary = c.is_ascii_uppercase()
                    && (p.is_ascii_lowercase()
                        || p.is_ascii_digit()
                        || (p.is_ascii_uppercase() && next_lower));
                if boundary {
                    close(s, i);
                    start = Some(i);
                }
            }
        }
    }
    if let Some(s) = start {
        close(s, key.len());
    }
    (
        prev.map(|(s, e)| slice(key, s, e)),
        last.map(|(s, e)| slice(key, s, e)),
    )
}

/// Delimiters ending an unquoted SR-001 value (TRD §6.2).
fn is_value_delim(c: u8) -> bool {
    c.is_ascii_whitespace()
        || c.is_ascii_control()
        || matches!(
            c,
            b',' | b';'
                | b'&'
                | b'"'
                | b'\''
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'<'
                | b'>'
        )
}

/// If a reserved placeholder starts at `v` and is followed by `delim` or the end, its end.
fn placeholder_at(b: &[u8], v: usize, delim: impl Fn(u8) -> bool) -> Option<usize> {
    let p = rules::PLACEHOLDERS
        .iter()
        .find(|p| slice(b, v, b.len()).starts_with(p.as_bytes()))?;
    let e = v + p.len();
    at(b, e).is_none_or(delim).then_some(e)
}

/// Position of the unescaped closing `q` at or after `from`, honoring backslash escapes.
fn closing_quote(b: &[u8], from: usize, end: usize, q: u8) -> Option<usize> {
    let mut i = from;
    while i < end {
        match at(b, i) {
            Some(b'\\') => i += 2,
            Some(c) if c == q => return Some(i),
            Some(_) => i += 1,
            None => return None,
        }
    }
    None
}

/// Redacts an SR-001 value starting at `v`; returns where scanning resumes.
fn secret_value(b: &[u8], v: usize, out: &mut Vec<Candidate>) -> usize {
    let rule = rules::rule_for(DetectorKind::NamedValue);
    let len = b.len();
    if v >= len {
        return v;
    }
    if let Some(e) = placeholder_at(b, v, is_value_delim) {
        return e;
    }
    match at(b, v) {
        Some(q @ (b'"' | b'\'')) => {
            let close = closing_quote(b, v + 1, len, q);
            push(out, v + 1, close.unwrap_or(len), rule);
            close.map_or(len, |c| c + 1)
        }
        _ => {
            let e = find_from(b, v, len, is_value_delim);
            let value = slice(b, v, e);
            if !rules::SKIP_VALUES.iter().any(|s| s.as_bytes() == value) {
                push(out, v, e, rule);
            }
            e
        }
    }
}

/// A field value: `(content start, content end, resume position)`. A quoted field ends at its
/// closing quote; an unquoted field runs to the end of the line.
fn field(b: &[u8], v: usize) -> (usize, usize, usize) {
    let len = b.len();
    match at(b, v) {
        Some(q @ (b'"' | b'\'')) => match closing_quote(b, v + 1, len, q) {
            Some(c) => (v + 1, c, c + 1),
            None => (v + 1, len, len),
        },
        _ => (v, len, len),
    }
}

fn is_cred_delim(c: u8) -> bool {
    c.is_ascii_whitespace()
        || c.is_ascii_control()
        || matches!(c, b'"' | b'\'' | b',' | b';' | b')' | b']' | b'}' | b'>')
}

fn is_token68(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

/// A recognized header can follow a cookie fragment on the same log line. It belongs to the
/// outer assignment pass, not the cookie value parser (for example, `Cookie: a=b; Authorization:
/// Bearer token`).
fn header_starts_at(b: &[u8], start: usize, end: usize) -> bool {
    let limit = end.min(start.saturating_add(MAX_KEY));
    let key_end = find_from(b, start, limit, |c| c == b':' || c.is_ascii_whitespace());
    at(b, key_end) == Some(b':')
        && matches!(
            classify(slice(b, start, key_end)),
            Some(KeyKind::Authorization | KeyKind::CookieRequest | KeyKind::CookieResponse)
        )
}

/// SR-002 (TRD §6.3): keep a recognized scheme; redact a single credential token, or a
/// parameter list to the end of the field. An unrecognized first word redacts the whole field.
/// Returns the end of the text this field covered.
fn authorization_value(b: &[u8], v: usize, out: &mut Vec<Candidate>) -> usize {
    let rule = rules::rule_for(DetectorKind::Authorization);
    let (fs, fe, resume) = field(b, v);
    if fs >= fe {
        return resume;
    }
    if let Some(e) = placeholder_at(b, fs, is_cred_delim) {
        return e;
    }
    let scheme_end = skip_while(b, fs, fe, |c| c.is_ascii_alphanumeric() || c == b'-');
    let cred = skip_while(b, scheme_end, fe, is_space);
    let known_scheme = scheme_end > fs
        && rules::AUTH_SCHEMES
            .iter()
            .any(|s| eq_ic(slice(b, fs, scheme_end), s));
    if known_scheme && cred >= fe {
        // A scheme name without a credential reveals nothing.
        return resume;
    }
    if !(known_scheme && cred > scheme_end) {
        push(out, fs, fe, rule);
        return resume;
    }
    if let Some(e) = placeholder_at(b, cred, is_cred_delim) {
        return e;
    }
    // token68 with optional `=` padding versus an auth-param list (`k=v`, `k="v"`).
    let run_end = skip_while(b, cred, fe, is_token68);
    let pad_end = skip_while(b, run_end, fe, |c| c == b'=');
    let is_param = pad_end > run_end
        && pad_end < fe
        && match at(b, pad_end) {
            Some(b'"' | b'\'') => {
                pad_end - run_end == 1
                    && at(b, pad_end + 1).is_some_and(|c| c.is_ascii_alphanumeric())
            }
            Some(c) => !is_cred_delim(c),
            None => false,
        };
    if is_param {
        push(out, cred, fe, rule);
        resume
    } else {
        let end = find_from(b, cred, fe, is_cred_delim);
        push(out, cred, end, rule);
        end
    }
}

/// SR-009 (TRD §6.10): redact cookie values, keeping names, separators, and Set-Cookie
/// attributes. Returns where the field's coverage ends: its end, or the start of a header that
/// follows on the same line.
fn cookie_value(b: &[u8], v: usize, response: bool, out: &mut Vec<Candidate>) -> usize {
    let rule = rules::rule_for(DetectorKind::Cookie);
    let (fs, fe, resume) = field(b, v);
    let mut p = fs;
    loop {
        p = skip_while(b, p, fe, is_space);
        if p >= fe {
            return resume;
        }
        if header_starts_at(b, p, fe) {
            return p;
        }
        let name_end = find_from(b, p, fe, |c| c == b'=' || c == b';');
        if at(b, name_end) != Some(b'=') {
            // A segment without a value: a Set-Cookie attribute or a bare flag.
            if response {
                return resume;
            }
            p = name_end + 1;
            continue;
        }
        let vs = name_end + 1;
        let raw_end = find_from(b, vs, fe, |c| c == b';' || c.is_ascii_control());
        let next = match at(b, vs) {
            Some(q @ (b'\'' | b'"')) => {
                let close = closing_quote(b, vs + 1, fe, q).unwrap_or(fe);
                let after = (close + 1).min(fe);
                if skip_while(b, after, fe, is_space) < raw_end {
                    // Text glued after the closing quote belongs to the same malformed value.
                    push(out, vs, raw_end, rule);
                    raw_end
                } else {
                    push(out, vs + 1, close, rule);
                    after
                }
            }
            _ => {
                let mut ve = raw_end;
                while ve > vs && before(b, ve).is_some_and(is_space) {
                    ve -= 1;
                }
                push(out, vs, ve, rule);
                raw_end
            }
        };
        if response {
            return resume;
        }
        p = next;
        if at(b, p) == Some(b';') {
            p += 1;
        }
    }
}

/// Space-separated flag values (`--password value`, `"--token", "value"`), TRD §6.2.
fn scan_flags(b: &[u8], out: &mut Vec<Candidate>) {
    let len = b.len();
    let mut i = 0;
    while let Some(rel) = memchr::memchr(b'-', slice(b, i, len)) {
        let p = i + rel;
        i = p + 1;
        let quote = match before(b, p) {
            None => None,
            Some(q @ (b'"' | b'\'')) => Some(q),
            Some(c) if c.is_ascii_whitespace() || matches!(c, b'[' | b'(' | b',') => None,
            Some(_) => continue,
        };
        let ke = skip_while(b, p, len, is_key_char);
        i = ke.max(p + 1);
        let key = slice(b, p, ke);
        if key.len() > MAX_KEY || !is_flag_shape(key) || !is_secret_key(key) {
            continue;
        }
        let mut q = ke;
        if let Some(qc) = quote {
            if at(b, q) != Some(qc) {
                continue;
            }
            q += 1;
            let after_space = skip_while(b, q, len, is_space);
            let after_comma = if at(b, after_space) == Some(b',') {
                skip_while(b, after_space + 1, len, is_space)
            } else {
                after_space
            };
            if after_comma == q {
                continue;
            }
            q = after_comma;
        } else {
            if !at(b, q).is_some_and(is_space) {
                continue;
            }
            q = skip_while(b, q, len, is_space);
        }
        if q >= len || at(b, q) == Some(b'-') {
            continue;
        }
        i = secret_value(b, q, out).max(i);
    }
}

/// `--long-option`, or a single-dash option written entirely in lower case (TRD §6.2 ruling:
/// mixed-case single-dash forms such as `-pSECRET` are attached values, not keys).
fn is_flag_shape(key: &[u8]) -> bool {
    match key {
        [b'-', b'-', rest @ ..] => rest.iter().any(u8::is_ascii_alphabetic),
        [b'-', rest @ ..] => {
            rest.len() > 1
                && rest.iter().any(u8::is_ascii_alphabetic)
                && !rest.iter().any(u8::is_ascii_uppercase)
        }
        _ => false,
    }
}
