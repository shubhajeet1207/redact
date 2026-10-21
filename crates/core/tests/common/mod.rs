#![allow(dead_code)]

use spymonk_redact_core::rules;
use spymonk_redact_core::{Limits, Options, RuleId, Summary, sanitize_bytes};

pub const PRIVATE_IP_ON: Options = Options {
    email: true,
    private_ip: true,
};
pub const EMAIL_OFF: Options = Options {
    email: false,
    private_ip: false,
};

pub fn run(input: &str, opts: Options) -> (String, Summary) {
    let (out, summary, _) = sanitize_bytes(input.as_bytes(), opts, Limits::default(), false)
        .unwrap_or_else(|e| panic!("sanitize failed on {input:?}: {e}"));
    (String::from_utf8(out).expect("output is UTF-8"), summary)
}

pub fn redact(input: &str) -> String {
    run(input, Options::default()).0
}

/// Count for a rule by catalog id, e.g. `count(&summary, "SR-001")`.
pub fn count(summary: &Summary, id: &str) -> u64 {
    let idx = (0..spymonk_redact_core::RULE_COUNT as u8)
        .find(|i| rules::rule_id_str(RuleId(*i)) == id)
        .unwrap_or_else(|| panic!("unknown rule {id}"));
    summary.by_rule[usize::from(idx)]
}

/// Asserts every `(input, expected)` pair under `opts` and reports all failures at once.
pub fn check_all(opts: Options, cases: &[(&str, &str)]) {
    let mut failures = Vec::new();
    for (input, expected) in cases {
        let got = run(input, opts).0;
        if got != *expected {
            failures.push(format!(
                "\n  input:    {input:?}\n  expected: {expected:?}\n  got:      {got:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) failed:{}",
        failures.len(),
        failures.join("")
    );
}

/// Asserts each input is left unchanged under `opts`.
pub fn unchanged_all(opts: Options, inputs: &[&str]) {
    let cases: Vec<(&str, &str)> = inputs.iter().map(|i| (*i, *i)).collect();
    check_all(opts, &cases);
}

/// Asserts a case and the rule it is attributed to.
pub fn attributed(input: &str, expected: &str, rule: &str, n: u64) {
    let (got, summary) = run(input, Options::default());
    assert_eq!(got, expected, "input {input:?}");
    assert_eq!(
        count(&summary, rule),
        n,
        "count for {rule} on {input:?}: {:?}",
        summary.by_rule
    );
    assert_eq!(summary.replacements, n, "total on {input:?}");
}
