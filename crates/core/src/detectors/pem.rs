//! SR-008 private-key blocks (TRD §6.9). The only detector with state across lines: inside a
//! multi-line block, body lines are removed (the first changed part becomes the placeholder),
//! armor lines are kept, and every separator is preserved. An unterminated block stays open to
//! the end of the input, so it fails closed.
//!
//! A candidate wholly inside a block is ignored by the detector coordinator, while a candidate
//! that crosses its armor remains available to overlap resolution. This preserves SR-008's own
//! semantics and still allows a quoted `private_key` value to resolve as required by FX-29.
#![allow(clippy::arithmetic_side_effects)] // Positions are bounded by the line length (≤ 64 MiB).

use alloc::vec::Vec;

use super::Finders;
use crate::model::RuleId;
use crate::resolve::{Candidate, Repl};
use crate::rules::{self, DetectorKind};
use crate::scan::{push_repl, skip_while, slice};

const RULE: RuleId = rules::rule_for(DetectorKind::PemBlock);

pub(crate) const BEGIN: &[u8] = b"-----BEGIN ";
pub(crate) const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

/// State carried across lines while inside a multi-line private-key block.
#[derive(Debug, Default)]
pub(crate) struct PemState {
    pub(crate) in_block: bool,
    /// Line number of the BEGIN armor of the open block.
    pub(crate) start_line: u64,
    label: Vec<u8>,
    /// A placeholder (inserted or pre-existing) already stands for this block.
    has_placeholder: bool,
}

impl PemState {
    /// Restores this state from `other`, reusing the label buffer.
    pub(crate) fn copy_from(&mut self, other: &PemState) {
        self.in_block = other.in_block;
        self.start_line = other.start_line;
        self.label.clone_from(&other.label);
        self.has_placeholder = other.has_placeholder;
    }
}

/// Processes the line's private-key structure. `owned` receives the byte ranges that belong to
/// blocks (armors and body), sorted and disjoint; the rest of the line is scanned by the other
/// detectors.
pub(crate) fn step(
    finders: &Finders,
    b: &[u8],
    st: &mut PemState,
    line_no: u64,
    out: &mut Vec<Candidate>,
    owned: &mut Vec<(usize, usize)>,
) {
    owned.clear();
    let mut from = 0;
    if st.in_block {
        let label = core::mem::take(&mut st.label);
        match find_end(finders, b, 0, &label) {
            None => {
                st.label = label;
                body(b, 0, b.len(), st, out);
                owned.push((0, b.len()));
                return;
            }
            Some((e, after)) => {
                body(b, 0, e, st, out);
                st.in_block = false;
                owned.push((0, after));
                from = after;
            }
        }
    }
    scan_begins(finders, b, from, st, line_no, out, owned);
}

/// Handles key body `b[s..e]`: the first changed part of a block becomes the placeholder,
/// later parts are removed, and a part that already is the placeholder is kept.
fn body(b: &[u8], s: usize, e: usize, st: &mut PemState, out: &mut Vec<Candidate>) {
    if s >= e {
        return;
    }
    if slice(b, s, e) == rules::placeholder(RULE).as_bytes() {
        st.has_placeholder = true;
    } else if st.has_placeholder {
        push_repl(out, s, e, RULE, Repl::Empty);
    } else {
        push_repl(out, s, e, RULE, Repl::Placeholder);
        st.has_placeholder = true;
    }
}

fn scan_begins(
    finders: &Finders,
    b: &[u8],
    from: usize,
    st: &mut PemState,
    line_no: u64,
    out: &mut Vec<Candidate>,
    owned: &mut Vec<(usize, usize)>,
) {
    let mut pos = from;
    while let Some(rel) = finders.pem_begin.find(slice(b, pos, b.len())) {
        let begin = pos + rel;
        let ls = begin + BEGIN.len();
        let le = skip_while(b, ls, b.len(), |c| {
            c.is_ascii_uppercase() || c.is_ascii_digit() || c == b' '
        });
        let label = slice(b, ls, le);
        if !slice(b, le, b.len()).starts_with(DASHES) || !is_private_label(label) {
            pos = ls;
            continue;
        }
        let body_start = le + DASHES.len();
        st.has_placeholder = false;
        match find_end(finders, b, body_start, label) {
            Some((e, after)) => {
                owned.push((begin, after));
                body(b, body_start, e, st, out);
                pos = after;
            }
            None => {
                owned.push((begin, b.len()));
                body(b, body_start, b.len(), st, out);
                st.in_block = true;
                st.label = label.to_vec();
                st.start_line = line_no;
                return;
            }
        }
    }
}

/// The first `-----END <label>-----` at or after `from`: `(armor start, armor end)`.
fn find_end(finders: &Finders, b: &[u8], from: usize, label: &[u8]) -> Option<(usize, usize)> {
    let mut pos = from;
    while let Some(rel) = finders.pem_end.find(slice(b, pos, b.len())) {
        let start = pos + rel;
        let ls = start + END.len();
        let rest = slice(b, ls, b.len());
        if rest.starts_with(label) && slice(rest, label.len(), rest.len()).starts_with(DASHES) {
            return Some((start, ls + label.len() + DASHES.len()));
        }
        pos = ls;
    }
    None
}

fn is_private_label(label: &[u8]) -> bool {
    rules::PEM_LABEL_SUFFIXES.iter().any(|suffix| {
        label.ends_with(suffix.as_bytes())
            && label.len() - suffix.len() <= rules::PEM_MAX_LABEL_PREFIX
            && (label.len() == suffix.len()
                || label.get(label.len() - suffix.len() - 1) == Some(&b' '))
    })
}
