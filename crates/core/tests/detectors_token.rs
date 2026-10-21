//! SR-007 known credential formats. Every value is synthetic.
mod common;
use common::*;
use spymonk_redact_core::Options;

fn rep(c: char, n: usize) -> String {
    std::iter::repeat_n(c, n).collect()
}

#[test]
fn sr007_every_format_redacts_a_synthetic_token() {
    let tokens = [
        format!("AKIA{}", "FAKEFAKEFAKE0000"),
        format!("ASIA{}", "FAKEFAKEFAKE0000"),
        format!("ghp_{}", rep('a', 36)),
        format!("ghs_{}", rep('Z', 40)),
        format!("github_pat_{}", rep('a', 82)),
        format!("glpat-{}", rep('x', 20)),
        format!("xoxb-{}", "1234567890-abcdef"),
        format!("xapp-{}", rep('1', 12)),
        format!("sk_live_{}", rep('a', 24)),
        format!("rk_test_{}", rep('b', 16)),
        format!("whsec_{}", rep('c', 32)),
        format!("AIza{}", rep('d', 35)),
        format!("sk-proj-{}", rep('e', 40)),
        format!("sk-ant-api03-{}", rep('f', 40)),
        format!("hf_{}", rep('g', 34)),
        format!("npm_{}", rep('h', 36)),
        format!("pypi-AgEIcHlwaS5vcmc{}", rep('i', 60)),
        format!("dckr_pat_{}", rep('j', 27)),
        format!("SG.{}.{}", rep('k', 22), rep('l', 43)),
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnX3BhcnQtYWJj".to_owned(),
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.".to_owned(),
    ];
    let mut failures = Vec::new();
    for t in &tokens {
        for (input, expected) in [
            (format!("key {t}"), "key [REDACTED]".to_owned()),
            (format!("x=\"{t}\";"), "x=\"[REDACTED]\";".to_owned()),
        ] {
            let (got, s) = run(&input, Options::default());
            if got != expected || count(&s, "SR-007") != 1 {
                failures.push(format!("{input:?} -> {got:?} ({:?})", s.by_rule));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn sr007_near_misses_unchanged() {
    let near: Vec<String> = vec![
        "AKIA-not-a-key".into(),
        format!("AKIA{}", "FAKEFAKEFAKE00001"),
        format!("AKIA{}", "FAKEFAKEFAKE000"),
        "ghp_short".into(),
        format!("xghp_{}", rep('a', 36)),
        format!("ghp_{}", rep('a', 35)),
        format!("AIza{}", rep('d', 34)),
        format!("AIza{}", rep('d', 36)),
        format!("npm_{}", rep('h', 35)),
        "xoxb-short".into(),
        "eyJabc".into(),
        "eyJhbGciOiJIUzI1NiJ9".into(),
        format!("SG.{}.{}", rep('k', 21), rep('l', 43)),
        "sk-not-a-key".into(),
    ];
    let refs: Vec<&str> = near.iter().map(String::as_str).collect();
    unchanged_all(Options::default(), &refs);
}

#[test]
fn sr007_takes_precedence_on_identical_range() {
    let t = format!("ghp_{}", rep('a', 36));
    attributed(
        &format!("\"token\": \"{t}\""),
        "\"token\": \"[REDACTED]\"",
        "SR-007",
        1,
    );
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2ln";
    attributed(
        &format!("Authorization: Bearer {jwt}"),
        "Authorization: Bearer [REDACTED]",
        "SR-007",
        1,
    );
}

#[test]
fn sr007_token_used_as_url_username() {
    let t = format!("ghp_{}", rep('a', 36));
    check_all(
        Options::default(),
        &[(
            &format!("https://{t}@github.com/o/r.git"),
            "https://[REDACTED]@github.com/o/r.git",
        )],
    );
}

#[test]
fn sr007_longer_run_redacted_whole() {
    let t = format!("ghp_{}", rep('a', 60));
    check_all(
        Options::default(),
        &[(&format!("{t} end"), "[REDACTED] end")],
    );
}

#[test]
fn exact_formats_need_a_trailing_boundary() {
    // TRD §6.8: an exact-length body must be followed by a boundary. Regression from the
    // idempotence property (`AKIA…0000fd12:3456::1`).
    unchanged_all(
        Options::default(),
        &[
            "AKIAFAKEFAKEFAKE0000x",
            "AKIAFAKEFAKEFAKE0000_x",
            "AKIAFAKEFAKEFAKE0000-x",
        ],
    );
    check_all(
        Options::default(),
        &[("AKIAFAKEFAKEFAKE0000.", "[REDACTED].")],
    );
    let input = "AKIAFAKEFAKEFAKE0000fd12:3456::1";
    let (once, _) = run(input, PRIVATE_IP_ON);
    assert_eq!(run(&once, PRIVATE_IP_ON).0, once);
}
