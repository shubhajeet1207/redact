//! TRD §9.6, §19.6: text and JSON reports, the review notice, and schema validation for success
//! and every failure code.
mod common;
use common::schema::{report_schema, validate};
use common::*;

use serde_json::Value;

fn json_report(args: &[&str], stdin: &[u8]) -> (Run, Value) {
    let mut all = vec!["--report-format", "json"];
    all.extend_from_slice(args);
    let r = run(&all, stdin);
    let doc: Value = serde_json::from_str(r.stderr.trim_end()).unwrap_or_else(|e| {
        panic!(
            "stderr is not exactly one JSON document ({e}): {}",
            r.stderr
        )
    });
    assert_eq!(r.stderr.lines().count(), 1, "one line of JSON");
    let errors = validate(&report_schema(), &doc);
    assert!(errors.is_empty(), "{errors:#?}\n{doc}");
    (r, doc)
}

#[test]
fn text_report_matches_the_documented_lines() {
    let r = run(
        ["--report"],
        b"password=CANARYcli1\nuser at /home/alex/x\nok\n",
    );
    assert_eq!(r.code, 0);
    let lines: Vec<&str> = r.stderr.lines().collect();
    assert_eq!(
        lines[0],
        "spymonk-redact: status=complete replacements=2 lines=3 email=on private_ip=off rules=1.0.0"
    );
    assert_eq!(lines[1], "spymonk-redact: SR-001=1 SR-004=1");
    assert_eq!(
        lines[2],
        "spymonk-redact: encoding=utf-8 bom=no hidden bidi=0 invisible=0 control=0 lone_cr=0"
    );
    assert_eq!(lines[3], format!("spymonk-redact: {NOTICE}"));
}

#[test]
fn text_report_says_none_without_replacements() {
    let r = run(["--report"], b"nothing here\n");
    assert!(
        r.stderr.lines().nth(1) == Some("spymonk-redact: none"),
        "{}",
        r.stderr
    );
}

#[test]
fn json_report_on_success_is_complete_and_valid() {
    let (r, doc) = json_report(&[], b"password=CANARYcli1\n");
    assert_eq!(r.code, 0);
    assert_eq!(doc["status"], "complete");
    assert_eq!(doc["outputComplete"], true);
    assert_eq!(doc["replacements"]["total"], 1);
    assert_eq!(doc["replacements"]["byRule"]["SR-001"], 1);
    assert_eq!(
        doc["replacements"]["byRule"].as_object().map(|m| m.len()),
        Some(9)
    );
    assert_eq!(doc["input"]["bytes"], 20);
    assert_eq!(doc["input"]["lines"], 1);
    assert_eq!(doc["output"]["bytes"], 20);
    assert_eq!(doc["error"], Value::Null);
    assert!(!r.stderr.contains("CANARY"));
}

/// Arguments, standard input, expected error code, and expected line.
type Case<'a> = (Vec<&'a str>, &'a [u8], &'a str, Option<u64>);

#[test]
fn every_failure_code_produces_a_valid_report() {
    let dir = temp_dir("report-fail");
    let input = dir.join("in.log");
    std::fs::write(&input, "x\n").expect("write");
    let target_dir = dir.join("a-dir");
    std::fs::create_dir(&target_dir).expect("dir");
    let in_path = input.to_str().expect("utf8").to_owned();
    let dir_path = target_dir.to_str().expect("utf8").to_owned();
    let missing = dir
        .join("missing")
        .join("o.log")
        .to_str()
        .expect("utf8")
        .to_owned();
    let cases: Vec<Case<'_>> = vec![
        (vec![], b"ok\n\xff\n", "INVALID_UTF8", Some(2)),
        (
            vec!["--input-encoding", "utf-16le"],
            b"a\x00b",
            "INVALID_UTF16",
            Some(1),
        ),
        (vec![], b"p\x00a\x00", "UTF16_WITHOUT_BOM", Some(1)),
        (vec![], b"\xFF\xFE\x00\x00", "UNSUPPORTED_ENCODING", Some(1)),
        (vec![], b"ok\na\x00\n", "NUL_BYTE", Some(2)),
        (
            vec!["--max-line-bytes", "1024"],
            &[b'z'; 1100],
            "LINE_TOO_LONG",
            Some(1),
        ),
        (vec![&dir_path], b"", "INPUT_READ_FAILED", None),
        (vec![&in_path, "-o", &in_path], b"", "OUTPUT_IS_INPUT", None),
        (vec!["-o", &dir_path], b"x\n", "OUTPUT_NOT_REGULAR", None),
        (vec!["-o", &missing], b"x\n", "OUTPUT_WRITE_FAILED", None),
    ];
    for (args, stdin, code, line) in cases {
        let (r, doc) = json_report(&args, stdin);
        assert_eq!(r.code, 1, "{code}");
        assert_eq!(doc["status"], "failed", "{code}");
        assert_eq!(doc["outputComplete"], false, "{code}");
        assert_eq!(doc["error"]["code"], code, "{doc}");
        assert_eq!(
            doc["error"]["line"],
            line.map_or(Value::Null, Value::from),
            "{code}"
        );
        assert!(!r.stderr.contains(&in_path), "no path in the report");
    }
}

#[test]
fn report_file_is_written_atomically_and_notices_stay_on_stderr() {
    let dir = temp_dir("report-file");
    let report = dir.join("report.json");
    let r = run(
        [
            "--report-format",
            "json",
            "--report-file",
            report.to_str().expect("utf8"),
        ],
        b"token=CANARYcli1\n",
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, b"token=[REDACTED]\n");
    assert_eq!(r.stderr.trim_end(), format!("spymonk-redact: {NOTICE}"));
    let text = std::fs::read_to_string(&report).expect("report");
    assert_no_canary(&text, "report file");
    let doc: Value = serde_json::from_str(&text).expect("JSON");
    assert!(validate(&report_schema(), &doc).is_empty());
    assert_eq!(entries(&dir), ["report.json"]);
}

#[test]
fn report_file_cannot_be_the_input() {
    let dir = temp_dir("report-input");
    let input = dir.join("in.log");
    std::fs::write(&input, "x\n").expect("write");
    let r = run(
        [
            input.as_os_str(),
            "--report-file".as_ref(),
            input.as_os_str(),
        ],
        b"",
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("OUTPUT_IS_INPUT"), "{}", r.stderr);
    assert_eq!(std::fs::read(&input).expect("read"), b"x\n");
}

#[test]
fn warnings_appear_in_both_formats() {
    let input = b"-----BEGIN PRIVATE KEY-----\nAAAA\n";
    let r = run(Vec::<&str>::new(), input);
    assert!(
        r.stderr.contains("UNTERMINATED_PRIVATE_KEY_BLOCK (line 1)"),
        "{}",
        r.stderr
    );
    let (_, doc) = json_report(&[], input);
    assert_eq!(doc["warnings"][0]["code"], "UNTERMINATED_PRIVATE_KEY_BLOCK");
    assert_eq!(doc["warnings"][0]["line"], 1);
}
