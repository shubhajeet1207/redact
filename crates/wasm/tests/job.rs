//! Native tests of the adapter logic that the WebAssembly exports wrap (TRD §7.3, §10.2, §10.4).
use spymonk_redact_core::{ErrorCode, Finding, RuleId};
use spymonk_redact_wasm::job::{
    FileCore, PASTE_LIMIT_BYTES, PREVIEW_BYTES, PasteOutcome, sanitize_paste, utf16_ranges,
};

fn f(start: u64, end: u64) -> Finding {
    Finding {
        start,
        end,
        rule: RuleId(0),
    }
}

#[test]
fn utf16_ranges_ascii_is_identity() {
    let text = "a=[REDACTED] b";
    assert_eq!(utf16_ranges(text, &[f(2, 12)], 0), vec![2, 12, 0]);
}

#[test]
fn utf16_ranges_count_code_units_not_bytes() {
    // "é" is 2 UTF-8 bytes and 1 UTF-16 unit; "🙂" is 4 bytes and 2 units; "e\u{301}" is 3 bytes, 2 units.
    let text = "é🙂e\u{301}[REDACTED]x";
    let start = "é🙂e\u{301}".len() as u64;
    let ranges = utf16_ranges(text, &[f(start, start + 10)], 0);
    assert_eq!(ranges, vec![5, 15, 0]);
}

#[test]
fn utf16_ranges_skip_a_leading_bom() {
    // Findings exclude the BOM bytes; UTF-16 offsets count the U+FEFF the string still contains.
    let text = "\u{FEFF}[USER]";
    assert_eq!(utf16_ranges(text, &[f(0, 6)], 3), vec![1, 7, 0]);
}

#[test]
fn paste_redacts_and_reports_utf16_ranges() {
    let PasteOutcome::Done {
        output,
        ranges,
        summary,
    } = sanitize_paste("🙂 password=hunter2".into(), true, false)
    else {
        panic!("paste failed");
    };
    assert_eq!(output, "🙂 password=[REDACTED]");
    assert_eq!(summary.replacements, 1);
    assert_eq!(ranges, vec![12, 22, 0]);
}

#[test]
fn paste_over_the_limit_fails_closed() {
    let text = "a".repeat(PASTE_LIMIT_BYTES + 1);
    match sanitize_paste(text, true, false) {
        PasteOutcome::Failed(e) => assert_eq!(e.code, ErrorCode::InputTooLarge),
        PasteOutcome::Done { .. } => panic!("over-limit paste was accepted"),
    }
}

#[test]
fn paste_with_nul_reports_nul_not_utf16() {
    match sanitize_paste("\0abc".into(), true, false) {
        PasteOutcome::Failed(e) => assert_eq!(e.code, ErrorCode::NulByte),
        PasteOutcome::Done { .. } => panic!("NUL accepted"),
    }
}

#[test]
fn file_core_streams_chunks_and_matches_whole_input() {
    let input = b"user=a\npassword=fake-one\nAuthorization: Bearer fake-two\n";
    let mut job = FileCore::new(true, false, 1_048_576).unwrap();
    let mut out = Vec::new();
    for chunk in input.chunks(5) {
        out.extend(job.push(chunk).unwrap());
    }
    out.extend(job.finish().unwrap());
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "user=a\npassword=[REDACTED]\nAuthorization: Bearer [REDACTED]\n"
    );
    let (preview, ranges) = job.preview();
    assert_eq!(
        preview,
        "user=a\npassword=[REDACTED]\nAuthorization: Bearer [REDACTED]\n"
    );
    assert_eq!(ranges, vec![16, 26, 0, 49, 59, 1]);
    assert_eq!(job.summary().map(|s| s.replacements), Some(2));
}

#[test]
fn file_core_preview_is_bounded_and_decodes_utf16() {
    let mut text = String::from("\u{FEFF}token=x\n");
    text.push_str(&"y".repeat(PREVIEW_BYTES * 2));
    let mut bytes = Vec::new();
    for unit in text.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    let mut job = FileCore::new(true, false, 67_108_864).unwrap();
    let mut out = job.push(&bytes).unwrap();
    out.extend(job.finish().unwrap());
    assert_eq!(&out[..2], &[0xFF, 0xFE], "UTF-16LE output keeps its BOM");
    let (preview, ranges) = job.preview();
    assert!(preview.len() <= PREVIEW_BYTES);
    assert!(preview.starts_with("\u{FEFF}token=[REDACTED]\n"));
    assert_eq!(ranges, vec![7, 17, 0]);
}

#[test]
fn file_core_error_is_reported_with_its_line() {
    let mut job = FileCore::new(true, false, 1024).unwrap();
    let long = format!("ok\n{}\n", "z".repeat(2048));
    let err = job.push(long.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::LineTooLong);
    assert_eq!(err.line, Some(2));
}
