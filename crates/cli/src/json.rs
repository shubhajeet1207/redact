//! Minimal JSON output. Reports contain only fixed codes, versions, numbers, and booleans, so a
//! serializer dependency is unnecessary; strings are still escaped per RFC 8259.

use std::fmt::Write as _;

pub fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON number or `null`.
pub fn opt_u64(out: &mut String, v: Option<u64>) {
    match v {
        Some(n) => {
            let _ = write!(out, "{n}");
        }
        None => out.push_str("null"),
    }
}
