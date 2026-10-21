//! Golden corpus runner (TRD §8.4, §19.2). Expected values are hand-written fixture data; this
//! runner never writes them. Every fixture is also run in small chunks to check invariant P-5.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use spymonk_redact_core::rules::{self, RULE_IDS};
use spymonk_redact_core::{
    CoreError, InputEncoding, InvalidUtf8, Limits, Options, Sanitizer, Summary, sanitize_bytes,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn files(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            files(&p, ext, out);
        } else if p.extension().is_some_and(|e| e == ext) {
            out.push(p);
        }
    }
}

#[derive(Debug, PartialEq)]
struct Run {
    out: Vec<u8>,
    result: Result<Summary, CoreError>,
}

fn run(input: &[u8], opts: Options, limits: Limits, chunk: usize) -> Run {
    let mut s =
        Sanitizer::new(opts, limits, InputEncoding::Auto, InvalidUtf8::Error, false).unwrap();
    let mut out = Vec::new();
    for c in input.chunks(chunk.max(1)) {
        if let Err(e) = s.push(c, &mut out) {
            return Run {
                out,
                result: Err(e),
            };
        }
    }
    let result = s.finish(&mut out);
    Run { out, result }
}

fn bytes(f: &Value, text: &str, b64: &str) -> Option<Vec<u8>> {
    if let Some(s) = f.get(text).and_then(Value::as_str) {
        return Some(s.as_bytes().to_vec());
    }
    f.get(b64)
        .and_then(Value::as_str)
        .map(|s| STANDARD.decode(s).unwrap())
}

fn rule_index(id: &str) -> usize {
    RULE_IDS
        .iter()
        .position(|r| *r == id)
        .unwrap_or_else(|| panic!("unknown rule {id}"))
}

fn check(f: &Value) -> Result<(), String> {
    let id = f["id"].as_str().unwrap_or("?");
    let input = bytes(f, "input", "inputBase64").ok_or("no input")?;
    let expected = bytes(f, "output", "outputBase64").ok_or("no output")?;
    let mut opts = Options::default();
    if let Some(o) = f.get("options") {
        opts.email = o
            .get("email")
            .and_then(Value::as_bool)
            .unwrap_or(opts.email);
        opts.private_ip = o
            .get("privateIp")
            .and_then(Value::as_bool)
            .unwrap_or(opts.private_ip);
    }
    let mut limits = Limits::default();
    if let Some(m) = f.get("maxLineBytes").and_then(Value::as_u64) {
        limits.max_line_bytes = u32::try_from(m).unwrap();
    }

    let whole = run(&input, opts, limits, input.len());
    for chunk in [1, 7] {
        let split = run(&input, opts, limits, chunk);
        if split != whole {
            return Err(format!(
                "{id}: chunk size {chunk} differs from whole input (P-5)"
            ));
        }
    }
    let show = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    if whole.out != expected {
        return Err(format!(
            "{id}: output\n    expected {:?}\n    got      {:?}",
            show(&expected),
            show(&whole.out)
        ));
    }

    match (f.get("error"), &whole.result) {
        (Some(err), Err(e)) => {
            let code = err["code"].as_str().unwrap_or_default();
            let line = err.get("line").and_then(Value::as_u64);
            if e.code.as_str() != code || e.line != line {
                return Err(format!(
                    "{id}: error {:?} line {:?}, expected {code} line {line:?}",
                    e.code, e.line
                ));
            }
            Ok(())
        }
        (Some(_), Ok(_)) => Err(format!("{id}: expected an error, got success")),
        (None, Err(e)) => Err(format!("{id}: unexpected error {e}")),
        (None, Ok(s)) => {
            let want_total = f["replacements"].as_u64().unwrap_or(0);
            if s.replacements != want_total {
                return Err(format!(
                    "{id}: replacements {} expected {want_total}",
                    s.replacements
                ));
            }
            let mut want = [0u64; spymonk_redact_core::RULE_COUNT];
            if let Some(by) = f.get("byRule").and_then(Value::as_object) {
                for (rule, n) in by {
                    want[rule_index(rule)] = n.as_u64().unwrap_or(0);
                }
            }
            if s.by_rule != want {
                return Err(format!("{id}: byRule {:?} expected {want:?}", s.by_rule));
            }
            let want_lines = f["lines"].as_u64().unwrap_or(0);
            if s.lines != want_lines {
                return Err(format!("{id}: lines {} expected {want_lines}", s.lines));
            }
            let warnings: Vec<&str> = s.warnings.iter().map(|w| w.code()).collect();
            let want_warnings: Vec<&str> = f
                .get("warnings")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if warnings != want_warnings {
                return Err(format!(
                    "{id}: warnings {warnings:?} expected {want_warnings:?}"
                ));
            }
            if let Some(h) = f.get("hidden") {
                let pairs = [
                    ("bidi", s.hidden.bidi),
                    ("invisible", s.hidden.invisible),
                    ("control", s.hidden.control),
                    ("loneCr", s.hidden.lone_cr),
                ];
                for (k, got) in pairs {
                    if let Some(w) = h.get(k).and_then(Value::as_u64)
                        && got != w
                    {
                        return Err(format!("{id}: hidden.{k} {got} expected {w}"));
                    }
                }
            }
            Ok(())
        }
    }
}

#[test]
fn golden_fixtures() {
    let mut paths = Vec::new();
    files(&root(), "json", &mut paths);
    let mut ids = std::collections::BTreeSet::new();
    let mut failures = Vec::new();
    for p in &paths {
        let doc: Value = serde_json::from_str(&fs::read_to_string(p).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        for f in doc["fixtures"].as_array().unwrap() {
            let id = f["id"].as_str().unwrap().to_owned();
            assert!(ids.insert(id.clone()), "duplicate fixture id {id}");
            if let Err(e) = check(f) {
                failures.push(e);
            }
        }
    }
    assert!(ids.len() >= 200, "corpus shrank to {} fixtures", ids.len());
    assert!(
        failures.is_empty(),
        "{} fixture(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The manifest's documented examples are executable: what the rule reference shows is what the
/// engine does (TRD §8.2).
#[test]
fn manifest_examples_and_non_examples() {
    let manifest: Value =
        serde_json::from_str(include_str!("../../../rules/rules.v1.json")).unwrap();
    let mut failures = Vec::new();
    for rule in manifest["rules"].as_array().unwrap() {
        let id = rule["id"].as_str().unwrap();
        // Default options, with this rule's own toggle switched on when it is off by default.
        let mut opts = Options::default();
        if rule["detector"] == "private-ip" {
            opts.private_ip = true;
        }
        for ex in rule["examples"].as_array().unwrap() {
            let (input, want) = (ex[0].as_str().unwrap(), ex[1].as_str().unwrap());
            let (out, s, _) =
                sanitize_bytes(input.as_bytes(), opts, Limits::default(), false).unwrap();
            let got = String::from_utf8(out).unwrap();
            if got != want || s.by_rule[rule_index(id)] == 0 {
                failures.push(format!("{id} example {input:?}: got {got:?}"));
            }
        }
        for ne in rule["nonExamples"].as_array().unwrap() {
            let input = ne.as_str().unwrap();
            let (_, s, _) =
                sanitize_bytes(input.as_bytes(), opts, Limits::default(), false).unwrap();
            if s.by_rule[rule_index(id)] != 0 {
                failures.push(format!("{id} non-example {input:?} matched"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(
        rules::RULES_VERSION,
        manifest["ruleVersion"].as_str().unwrap()
    );
}

/// Benign corpus gate (PRD §11): at most 0.5% of lines change, and every change is listed for
/// review.
#[test]
fn benign_corpus_change_rate() {
    let mut paths = Vec::new();
    files(&root().join("benign"), "log", &mut paths);
    let (mut total, mut changed) = (0usize, 0usize);
    for p in &paths {
        let input = fs::read(p).unwrap();
        let (out, _, _) =
            sanitize_bytes(&input, Options::default(), Limits::default(), false).unwrap();
        let before = String::from_utf8(input).unwrap();
        let after = String::from_utf8(out).unwrap();
        for (a, b) in before.lines().zip(after.lines()) {
            total += 1;
            if a != b {
                changed += 1;
                eprintln!(
                    "benign change in {}:\n  - {a}\n  + {b}",
                    p.file_name().unwrap().to_string_lossy()
                );
            }
        }
        assert_eq!(
            before.lines().count(),
            after.lines().count(),
            "{}",
            p.display()
        );
    }
    assert!(total >= 100, "benign corpus too small: {total} lines");
    assert!(
        changed * 1000 <= total * 5,
        "{changed} of {total} benign lines changed (> 0.5%)"
    );
}
