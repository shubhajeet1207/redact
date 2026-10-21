//! TRD §19.6 parity: for every fixture and for generated inputs, the CLI, `sanitize_bytes`, the
//! WebAssembly streaming job (file mode), and paste mode give byte-identical output and equal
//! summaries. Paste mode applies to valid UTF-8 of at most 1 MiB, as in the browser.
mod common;
use common::*;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use proptest::prelude::*;
use serde_json::Value;
use spymonk_redact_core::{Limits, Options, Summary, sanitize_bytes};
use spymonk_redact_wasm::job::{FileCore, PASTE_LIMIT_BYTES, PasteOutcome, sanitize_paste};

struct Case {
    id: String,
    input: Vec<u8>,
    options: Options,
    max_line_bytes: u32,
}

fn fixtures() -> Vec<Case> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let mut cases = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("fixtures dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
                .expect("fixture JSON");
            for f in doc["fixtures"].as_array().into_iter().flatten() {
                let input = match (f.get("input"), f.get("inputBase64")) {
                    (Some(Value::String(s)), _) => s.as_bytes().to_vec(),
                    (_, Some(Value::String(b))) => STANDARD.decode(b).expect("base64"),
                    _ => continue,
                };
                let mut options = Options::default();
                if let Some(o) = f.get("options") {
                    options.email = o["email"].as_bool().unwrap_or(options.email);
                    options.private_ip = o["privateIp"].as_bool().unwrap_or(options.private_ip);
                }
                let max_line_bytes = f["maxLineBytes"]
                    .as_u64()
                    .and_then(|m| u32::try_from(m).ok())
                    .unwrap_or(1_048_576);
                cases.push(Case {
                    id: f["id"].as_str().unwrap_or("?").to_owned(),
                    input,
                    options,
                    max_line_bytes,
                });
            }
        }
    }
    assert!(cases.len() > 200, "fixture corpus found");
    cases
}

/// Output and summary, or `None` after an error.
type Result = (Vec<u8>, Option<Summary>);

fn core(input: &[u8], options: Options, max_line_bytes: u32) -> Result {
    let limits = Limits {
        max_line_bytes,
        max_total_bytes: None,
    };
    match sanitize_bytes(input, options, limits, false) {
        Ok((out, summary, _)) => (out, Some(summary)),
        Err(_) => (Vec::new(), None),
    }
}

fn file_job(input: &[u8], options: Options, max_line_bytes: u32) -> Result {
    let mut job = FileCore::new(options.email, options.private_ip, max_line_bytes).expect("job");
    let mut out = Vec::new();
    for chunk in input.chunks(1_048_576) {
        match job.push(chunk) {
            Ok(bytes) => out.extend(bytes),
            Err(_) => return (Vec::new(), None),
        }
    }
    match job.finish() {
        Ok(bytes) => {
            out.extend(bytes);
            (out, job.summary().cloned())
        }
        Err(_) => (Vec::new(), None),
    }
}

/// CLI stdout and its JSON report's counts, or `None` after a failure.
fn cli(case: &Case) -> (Vec<u8>, Option<Value>) {
    let mut args = vec![
        "--escape-controls".to_owned(),
        "never".to_owned(),
        "--report-format".to_owned(),
        "json".to_owned(),
        "--max-line-bytes".to_owned(),
        case.max_line_bytes.to_string(),
    ];
    if !case.options.email {
        args.push("--disable-email".into());
    }
    if case.options.private_ip {
        args.push("--enable-private-ip".into());
    }
    let r = run(&args, &case.input);
    let report: Value = serde_json::from_str(r.stderr.trim()).expect("one JSON report");
    if r.code == 0 {
        (r.stdout, Some(report))
    } else {
        (r.stdout, None)
    }
}

/// The CLI report's counts equal the engine summary's.
fn assert_report_matches(report: &Value, summary: &Summary, what: &str) {
    assert_eq!(
        report["replacements"]["total"], summary.replacements,
        "{what}: total"
    );
    for (i, n) in summary.by_rule.iter().enumerate() {
        let id = format!("SR-{:03}", i + 1);
        assert_eq!(report["replacements"]["byRule"][&id], *n, "{what}: {id}");
    }
    assert_eq!(report["input"]["lines"], summary.lines, "{what}: lines");
    assert_eq!(
        report["hidden"]["bidi"], summary.hidden.bidi,
        "{what}: bidi"
    );
    assert_eq!(
        report["hidden"]["loneCr"], summary.hidden.lone_cr,
        "{what}: lone CR"
    );
    assert_eq!(
        report["output"]["bytes"], summary.bytes_out,
        "{what}: output bytes"
    );
}

fn assert_paste_matches(input: &[u8], options: Options, expected: &Result, what: &str) {
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    if input.len() > PASTE_LIMIT_BYTES {
        return;
    }
    match (
        sanitize_paste(text.to_owned(), options.email, options.private_ip),
        expected,
    ) {
        (
            PasteOutcome::Done {
                output, summary, ..
            },
            (out, Some(s)),
        ) => {
            assert_eq!(output.as_bytes(), out.as_slice(), "{what}: paste output");
            assert_eq!(*summary, *s, "{what}: paste summary");
        }
        (PasteOutcome::Failed(_), (_, None)) => {}
        (PasteOutcome::Done { .. }, (_, None)) => {
            // Paste mode reads UTF-8 explicitly, so a probable-UTF-16 input is a NUL error in the
            // CLI's auto mode and also an error here; any other mismatch is a defect.
            panic!("{what}: paste succeeded where the engine failed");
        }
        (PasteOutcome::Failed(e), (_, Some(_))) => {
            panic!("{what}: paste failed ({e:?}) where the engine succeeded")
        }
    }
}

#[test]
fn every_fixture_is_identical_across_surfaces() {
    for case in fixtures() {
        let engine = core(&case.input, case.options, case.max_line_bytes);
        let streamed = file_job(&case.input, case.options, case.max_line_bytes);
        assert_eq!(streamed.0, engine.0, "{}: file-mode output", case.id);
        assert_eq!(streamed.1, engine.1, "{}: file-mode summary", case.id);
        let (cli_out, report) = cli(&case);
        match (&report, &engine.1) {
            (Some(report), Some(summary)) => {
                assert_eq!(cli_out, engine.0, "{}: CLI output", case.id);
                assert_report_matches(report, summary, &case.id);
            }
            (None, None) => {}
            _ => panic!("{}: CLI and engine disagree on success", case.id),
        }
        if case.max_line_bytes == 1_048_576 {
            assert_paste_matches(&case.input, case.options, &engine, &case.id);
        }
    }
}

const FRAGMENTS: &[&str] = &[
    "password=",
    "token: ",
    "\"api_key\": \"",
    "\"",
    " ",
    "\t",
    "=",
    ";",
    "Authorization: Bearer ",
    "Cookie: a=",
    "https://u:p@h/",
    "/home/alex/",
    "C:\\Users\\alex\\",
    "a@example.com",
    "10.0.0.8",
    "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "-----BEGIN PRIVATE KEY-----",
    "-----END PRIVATE KEY-----",
    "MIIE",
    "\n",
    "\r\n",
    "\r",
    "[REDACTED]",
    "x",
    "🙂",
    "e\u{301}",
    "\u{202E}",
    "\u{FEFF}",
];

fn text() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(FRAGMENTS), 0..40).prop_map(|v| v.concat())
}

fn cases() -> u32 {
    // TRD §19.6 asks for 10^5 generated inputs per run; debug builds run fewer.
    if cfg!(debug_assertions) {
        5_000
    } else {
        100_000
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), .. ProptestConfig::default() })]

    #[test]
    fn generated_inputs_are_identical_across_in_process_surfaces(
        input in text(),
        email in any::<bool>(),
        private_ip in any::<bool>(),
    ) {
        let options = Options { email, private_ip };
        let engine = core(input.as_bytes(), options, 1_048_576);
        let streamed = file_job(input.as_bytes(), options, 1_048_576);
        prop_assert_eq!(&streamed.0, &engine.0);
        prop_assert_eq!(&streamed.1, &engine.1);
        assert_paste_matches(input.as_bytes(), options, &engine, &input);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

    /// The CLI's chunked reading and writing add nothing: a subprocess per input, so fewer cases.
    #[test]
    fn generated_inputs_are_identical_through_the_cli(input in text()) {
        let case = Case { id: String::new(), input: input.into_bytes(), options: Options::default(), max_line_bytes: 1_048_576 };
        let engine = core(&case.input, case.options, case.max_line_bytes);
        let (cli_out, report) = cli(&case);
        prop_assert_eq!(&cli_out, &engine.0);
        if let (Some(report), Some(summary)) = (&report, &engine.1) {
            assert_report_matches(report, summary, "generated");
        }
    }
}
