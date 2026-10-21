//! Overlap resolution and emission (TRD §7.1 steps 5–7).
//!
//! Candidates from all detectors are normalized, sorted, and grouped by strict overlap
//! (touching ranges stay separate). Each group is replaced once:
//! - a single candidate uses its rule's placeholder;
//! - identical ranges use the highest-precedence rule's placeholder;
//! - differing ranges are replaced by their union, with the shared placeholder when every
//!   candidate agrees, otherwise `[REDACTED]`.
//!
//! The replacement is attributed to the highest-precedence rule in the group. Unchanged slices
//! are copied verbatim, so bytes outside replaced spans are preserved exactly (invariant P-1).

use alloc::string::String;
use alloc::vec::Vec;

use crate::model::{Finding, RULE_COUNT, RuleId};
use crate::rules;

/// Placeholder for a union of candidates whose placeholders differ (TRD §7.1).
pub const UNION_PLACEHOLDER: &str = "[REDACTED]";

/// How a candidate's range is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repl {
    /// The rule's reserved placeholder; counted and reported as a finding.
    Placeholder,
    /// Removed without a placeholder (private-key body continuation lines, TRD §6.9);
    /// never counted.
    Empty,
}

/// A detector's proposed replacement: a half-open byte range of the original line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub start: u32,
    pub end: u32,
    pub rule: RuleId,
    pub repl: Repl,
}

impl Candidate {
    fn text(&self) -> &'static str {
        match self.repl {
            Repl::Placeholder => rules::placeholder(self.rule),
            Repl::Empty => "",
        }
    }
}

/// One replaced group: the half-open range of the input line and its replacement's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edit {
    pub start: u32,
    pub end: u32,
    pub len: u32,
}

/// Writes the sanitized `line` to `out` and returns the number of placeholders inserted.
///
/// `counts` is incremented per inserted placeholder. When `findings` is given, each inserted
/// placeholder's range is recorded as `out_base + offset within out`.
pub fn resolve(
    line: &str,
    cands: &mut Vec<Candidate>,
    out: &mut String,
    counts: &mut [u64; RULE_COUNT],
    findings: Option<&mut Vec<Finding>>,
    out_base: u64,
) -> u64 {
    let mut inserted = Vec::new();
    resolve_into(line, cands, out, &mut inserted, &mut Vec::new());
    for f in &inserted {
        if let Some(c) = counts.get_mut(usize::from(f.rule.0)) {
            *c = c.saturating_add(1);
        }
    }
    if let Some(all) = findings {
        all.extend(inserted.iter().map(|f| Finding {
            start: out_base.saturating_add(f.start),
            end: out_base.saturating_add(f.end),
            rule: f.rule,
        }));
    }
    to_u64(inserted.len())
}

/// Writes the sanitized `line` to `out`. `findings` receives each inserted placeholder's range,
/// relative to where `out` ended on entry; `edits` receives every replaced group in line order.
pub(crate) fn resolve_into(
    line: &str,
    cands: &mut Vec<Candidate>,
    out: &mut String,
    findings: &mut Vec<Finding>,
    edits: &mut Vec<Edit>,
) {
    let len = line.len();
    // Normalize: clamp to the line, widen to character boundaries (redacting more, never
    // splitting a character), and drop empty ranges and targets that already are placeholders.
    cands.retain_mut(|candidate| {
        let mut start = usize::try_from(candidate.start)
            .unwrap_or(usize::MAX)
            .min(len);
        let mut end = usize::try_from(candidate.end)
            .unwrap_or(usize::MAX)
            .min(len);
        while start > 0 && !line.is_char_boundary(start) {
            start = start.saturating_sub(1);
        }
        while end < len && !line.is_char_boundary(end) {
            end = end.saturating_add(1);
        }
        if start >= end
            || line
                .get(start..end)
                .is_some_and(|text| rules::is_placeholder_sequence(text.as_bytes()))
        {
            return false;
        }
        match (u32::try_from(start), u32::try_from(end)) {
            (Ok(s), Ok(e)) => {
                candidate.start = s;
                candidate.end = e;
                true
            }
            _ => false,
        }
    });
    cands.sort_unstable_by_key(|c| (c.start, c.end, rules::rank(c.rule)));

    let base_len = out.len();
    let mut pos = 0usize;
    let mut iter = cands.iter().copied().peekable();
    while let Some(first) = iter.next() {
        let mut group_end = first.end;
        let mut best = first;
        let mut same_range = true;
        let mut shared = Some(first.text());
        let mut members = 1u32;
        while let Some(next) = iter.next_if(|n| n.start < group_end) {
            same_range &= next.start == first.start && next.end == first.end;
            group_end = group_end.max(next.end);
            if rules::rank(next.rule) < rules::rank(best.rule) {
                best = next;
            }
            if shared != Some(next.text()) {
                shared = None;
            }
            members = members.saturating_add(1);
        }
        let text = if members == 1 || same_range {
            best.text()
        } else {
            shared.unwrap_or(UNION_PLACEHOLDER)
        };

        let start = usize::try_from(first.start).unwrap_or(len);
        out.push_str(line.get(pos..start).unwrap_or_default());
        if !text.is_empty() {
            let offset = to_u64(out.len().saturating_sub(base_len));
            out.push_str(text);
            findings.push(Finding {
                start: offset,
                end: offset.saturating_add(to_u64(text.len())),
                rule: best.rule,
            });
        }
        edits.push(Edit {
            start: first.start,
            end: group_end,
            len: u32::try_from(text.len()).unwrap_or(u32::MAX),
        });
        pos = usize::try_from(group_end).unwrap_or(len);
    }
    out.push_str(line.get(pos..).unwrap_or_default());
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
