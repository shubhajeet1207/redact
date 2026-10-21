//! SR-006 private IP addresses (TRD §6.7): RFC 1918 IPv4 and IPv6 unique-local addresses,
//! matched with explicit grammars and the manifest's ranges. Every parse starts at a token
//! boundary and reads at most a few dozen bytes, so the scan is linear.
#![allow(clippy::arithmetic_side_effects)] // Positions are bounded by the line length (≤ 64 MiB).

use alloc::vec::Vec;

use crate::model::RuleId;
use crate::resolve::Candidate;
use crate::rules;
use crate::scan::{at, before, push};

pub(crate) fn detect(b: &[u8], rule: RuleId, out: &mut Vec<Candidate>) {
    let mut i = 0;
    while let Some(c) = at(b, i) {
        let parsed = if c.is_ascii_digit()
            && !before(b, i).is_some_and(|p| p.is_ascii_alphanumeric() || p == b'_' || p == b'.')
        {
            parse_v4(b, i).map(|(end, a)| (end, v4_private(a)))
        } else if matches!(c, b'f' | b'F')
            && at(b, i + 1).is_some_and(|n| matches!(n, b'c' | b'C' | b'd' | b'D'))
            && !before(b, i)
                .is_some_and(|p| p.is_ascii_alphanumeric() || matches!(p, b'_' | b':' | b'.'))
        {
            parse_v6(b, i).map(|(end, a)| (end, v6_private(a)))
        } else {
            None
        };
        if let Some((end, private)) = parsed {
            if private {
                push(out, i, end, rule);
            }
            i = end;
            continue;
        }
        i += 1;
    }
}

fn v4_private(addr: u32) -> bool {
    rules::IPV4_RANGES.iter().any(|&(net, len)| {
        let mask = if len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(len))
        };
        addr & mask == net
    })
}

fn v6_private(addr: u128) -> bool {
    rules::IPV6_RANGES.iter().any(|&(net, len)| {
        let mask = if len == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(len))
        };
        addr & mask == net
    })
}

/// Dotted-quad IPv4 at `i`: four decimal octets 0–255, no leading zeros, with a trailing token
/// boundary (a following `.` must not start another number).
fn parse_v4(b: &[u8], i: usize) -> Option<(usize, u32)> {
    let mut pos = i;
    let mut addr: u32 = 0;
    for k in 0..4 {
        if k > 0 {
            if at(b, pos) != Some(b'.') {
                return None;
            }
            pos += 1;
        }
        let s = pos;
        let mut octet: u32 = 0;
        while let Some(d) = at(b, pos).filter(u8::is_ascii_digit) {
            if pos - s == 3 {
                return None;
            }
            octet = octet * 10 + u32::from(d - b'0');
            pos += 1;
        }
        let digits = pos - s;
        if digits == 0 || octet > 255 || (digits > 1 && at(b, s) == Some(b'0')) {
            return None;
        }
        addr = (addr << 8) | octet;
    }
    match at(b, pos) {
        Some(c) if c.is_ascii_alphanumeric() || c == b'_' => None,
        Some(b'.') if at(b, pos + 1).is_some_and(|c| c.is_ascii_digit()) => None,
        _ => Some((pos, addr)),
    }
}

fn hex(c: u8) -> Option<u32> {
    char::from(c).to_digit(16)
}

/// RFC 4291 text form at `i`: groups of 1–4 hex digits, at most one `::`, optional dotted-quad
/// tail. Returns the end and the 128-bit value.
fn parse_v6(b: &[u8], i: usize) -> Option<(usize, u128)> {
    let mut head: Vec<u16> = Vec::with_capacity(8);
    let mut tail: Vec<u16> = Vec::with_capacity(8);
    let mut compressed = false;
    let mut pos = i;
    loop {
        let gs = pos;
        let mut value: u32 = 0;
        while let Some(h) = at(b, pos).and_then(hex) {
            if pos - gs == 4 {
                return None;
            }
            value = value * 16 + h;
            pos += 1;
        }
        if pos == gs {
            // Only a trailing `::` may end without a group.
            if compressed && before(b, pos) == Some(b':') {
                break;
            }
            return None;
        }
        if at(b, pos) == Some(b'.') {
            let (end, v4) = parse_v4(b, gs)?;
            let groups = if compressed { &mut tail } else { &mut head };
            groups.push(u16::try_from(v4 >> 16).ok()?);
            groups.push(u16::try_from(v4 & 0xFFFF).ok()?);
            pos = end;
            break;
        }
        let groups = if compressed { &mut tail } else { &mut head };
        groups.push(u16::try_from(value).ok()?);
        if head.len() + tail.len() > 8 {
            return None;
        }
        if at(b, pos) != Some(b':') {
            break;
        }
        if at(b, pos + 1) == Some(b':') {
            if compressed {
                return None;
            }
            compressed = true;
            pos += 2;
            if !at(b, pos).and_then(hex).is_some() {
                break;
            }
        } else {
            pos += 1;
            if !at(b, pos).and_then(hex).is_some() {
                return None;
            }
        }
    }
    let total = head.len() + tail.len();
    if (compressed && total > 7) || (!compressed && total != 8) {
        return None;
    }
    if at(b, pos).is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b':' | b'.' | b'_')) {
        return None;
    }
    let mut addr: u128 = 0;
    for g in &head {
        addr = (addr << 16) | u128::from(*g);
    }
    // `total` is 1..=8, so the shift is at most 112 bits.
    addr <<= 16 * u32::try_from(8 - total).ok()?;
    for g in &tail {
        addr = (addr << 16) | u128::from(*g);
    }
    Some((pos, addr))
}
