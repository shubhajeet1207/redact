use spymonk_redact_core::resolve::{Candidate, Repl, resolve};
use spymonk_redact_core::rules::{IDX_EMAIL, IDX_NAMED_VALUE, IDX_TOKEN_FORMAT};
use spymonk_redact_core::{Finding, RULE_COUNT, RuleId};

fn rid(idx: usize) -> RuleId {
    RuleId(idx as u8)
}

fn cand(start: u32, end: u32, idx: usize) -> Candidate {
    Candidate {
        start,
        end,
        rule: rid(idx),
        repl: Repl::Placeholder,
    }
}

struct Out {
    text: String,
    counts: [u64; RULE_COUNT],
    inserted: u64,
    findings: Vec<Finding>,
}

fn run(line: &str, mut cands: Vec<Candidate>, base: u64) -> Out {
    let mut text = String::new();
    let mut counts = [0u64; RULE_COUNT];
    let mut findings = Vec::new();
    let inserted = resolve(
        line,
        &mut cands,
        &mut text,
        &mut counts,
        Some(&mut findings),
        base,
    );
    Out {
        text,
        counts,
        inserted,
        findings,
    }
}

#[test]
fn no_candidates_copies_line() {
    let o = run("plain text ✓", vec![], 0);
    assert_eq!(o.text, "plain text ✓");
    assert_eq!(o.inserted, 0);
}

#[test]
fn isolated_candidate_gets_rule_placeholder() {
    let o = run("password=abc rest", vec![cand(9, 12, IDX_NAMED_VALUE)], 0);
    assert_eq!(o.text, "password=[REDACTED] rest");
    assert_eq!(o.counts[IDX_NAMED_VALUE], 1);
    assert_eq!(o.inserted, 1);
}

#[test]
fn identical_ranges_use_precedence() {
    let o = run(
        "t=ghp_x",
        vec![cand(2, 7, IDX_NAMED_VALUE), cand(2, 7, IDX_TOKEN_FORMAT)],
        0,
    );
    assert_eq!(o.text, "t=[REDACTED]");
    assert_eq!(o.counts[IDX_TOKEN_FORMAT], 1);
    assert_eq!(o.counts[IDX_NAMED_VALUE], 0);
}

#[test]
fn differing_overlap_unions_to_redacted() {
    let o = run(
        "0123456789abcdefXYZ",
        vec![cand(5, 15, IDX_EMAIL), cand(0, 10, IDX_NAMED_VALUE)],
        0,
    );
    assert_eq!(o.text, "[REDACTED]fXYZ");
    assert_eq!(o.counts[IDX_NAMED_VALUE], 1);
    assert_eq!(o.counts[IDX_EMAIL], 0);
    assert_eq!(o.inserted, 1);
}

#[test]
fn same_placeholder_union_keeps_it() {
    let o = run(
        "aaaaaaaaaa",
        vec![cand(0, 5, IDX_EMAIL), cand(3, 8, IDX_EMAIL)],
        0,
    );
    assert_eq!(o.text, "[EMAIL REDACTED]aa");
    assert_eq!(o.counts[IDX_EMAIL], 1);
}

#[test]
fn chained_overlaps_form_one_group() {
    let o = run(
        "abcdefghij",
        vec![
            cand(0, 3, IDX_EMAIL),
            cand(2, 6, IDX_EMAIL),
            cand(5, 9, IDX_EMAIL),
        ],
        0,
    );
    assert_eq!(o.text, "[EMAIL REDACTED]j");
    assert_eq!(o.counts[IDX_EMAIL], 1);
}

#[test]
fn touching_ranges_stay_separate() {
    let o = run(
        "abcdef",
        vec![cand(3, 6, IDX_NAMED_VALUE), cand(0, 3, IDX_NAMED_VALUE)],
        0,
    );
    assert_eq!(o.text, "[REDACTED][REDACTED]");
    assert_eq!(o.counts[IDX_NAMED_VALUE], 2);
}

#[test]
fn exact_placeholder_target_is_discarded() {
    let o = run(
        "x=[USER] y=[REDACTED]",
        vec![cand(2, 8, IDX_NAMED_VALUE), cand(11, 21, IDX_NAMED_VALUE)],
        0,
    );
    assert_eq!(o.text, "x=[USER] y=[REDACTED]");
    assert_eq!(o.inserted, 0);
}

#[test]
fn empty_repl_removes_text_without_placeholder() {
    let line = "MIIEvQIBADANBgkq";
    let mut c = cand(0, line.len() as u32, IDX_NAMED_VALUE);
    c.repl = Repl::Empty;
    let o = run(line, vec![c], 0);
    assert_eq!(o.text, "");
    assert_eq!(o.inserted, 0);
    assert_eq!(o.counts, [0; RULE_COUNT]);
}

#[test]
fn findings_record_output_ranges_from_base() {
    let o = run(
        "a=1 b=22",
        vec![cand(2, 3, IDX_NAMED_VALUE), cand(6, 8, IDX_EMAIL)],
        100,
    );
    assert_eq!(o.text, "a=[REDACTED] b=[EMAIL REDACTED]");
    assert_eq!(
        o.findings,
        [
            Finding {
                start: 102,
                end: 112,
                rule: rid(IDX_NAMED_VALUE)
            },
            Finding {
                start: 115,
                end: 131,
                rule: rid(IDX_EMAIL)
            },
        ]
    );
}

#[test]
fn candidate_inside_multibyte_char_is_widened_never_split() {
    let o = run("aé", vec![cand(2, 3, IDX_NAMED_VALUE)], 0);
    assert_eq!(o.text, "a[REDACTED]");
}

#[test]
fn out_of_range_and_empty_candidates_are_safe() {
    let o = run(
        "abc",
        vec![cand(1, 99, IDX_NAMED_VALUE), cand(2, 2, IDX_EMAIL)],
        0,
    );
    assert_eq!(o.text, "a[REDACTED]");
    assert_eq!(o.inserted, 1);
}

#[test]
fn target_made_only_of_placeholders_is_discarded() {
    let line = "v=[REDACTED][EMAIL REDACTED] [USER] end";
    let o = run(line, vec![cand(2, 35, IDX_NAMED_VALUE)], 0);
    assert_eq!(o.text, line);
    assert_eq!(o.inserted, 0);
    let mixed = "v=[REDACTED]x";
    assert_eq!(
        run(mixed, vec![cand(2, 13, IDX_NAMED_VALUE)], 0).text,
        "v=[REDACTED]"
    );
}
