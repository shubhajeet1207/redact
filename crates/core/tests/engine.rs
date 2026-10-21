use spymonk_redact_core::{
    EncodingKind, ErrorCode, InputEncoding, InvalidUtf8, Limits, Options, RULE_COUNT, Sanitizer,
    sanitize_bytes,
};

fn run_chunked(input: &[u8], chunk: usize) -> (Vec<u8>, spymonk_redact_core::Summary) {
    let mut s = Sanitizer::new(
        Options::default(),
        Limits::default(),
        InputEncoding::Auto,
        InvalidUtf8::Error,
        false,
    )
    .unwrap();
    let mut out = Vec::new();
    for c in input.chunks(chunk.max(1)) {
        s.push(c, &mut out).unwrap();
    }
    let summary = s.finish(&mut out).unwrap();
    (out, summary)
}

#[test]
fn identity_preserves_bytes_and_counts_lines() {
    let input = "a\r\nb\rc\n\nlast ✓".as_bytes();
    let (out, summary, findings) =
        sanitize_bytes(input, Options::default(), Limits::default(), true).unwrap();
    assert_eq!(out, input);
    assert_eq!(summary.lines, 5);
    assert_eq!(summary.replacements, 0);
    assert_eq!(summary.by_rule, [0; RULE_COUNT]);
    assert_eq!(summary.bytes_in, input.len() as u64);
    assert_eq!(summary.bytes_out, input.len() as u64);
    assert_eq!(summary.hidden.lone_cr, 1);
    assert!(findings.is_empty());
    assert_eq!(summary.rules_version, "1.0.0");
    assert_eq!(summary.rules_sha256.len(), 64);
}

#[test]
fn empty_input_produces_empty_output() {
    let (out, summary, _) =
        sanitize_bytes(b"", Options::default(), Limits::default(), false).unwrap();
    assert!(out.is_empty());
    assert_eq!(summary.lines, 0);
}

#[test]
fn chunking_does_not_change_identity_output() {
    let input = "one\r\ntwo\rthree\n€🙂\r".as_bytes();
    let (whole, ws) = run_chunked(input, input.len());
    let (bytewise, bs) = run_chunked(input, 1);
    assert_eq!(whole, input);
    assert_eq!(bytewise, input);
    assert_eq!(ws, bs);
}

#[test]
fn bom_reemitted() {
    let input = b"\xEF\xBB\xBFhi\n";
    let (out, summary, _) =
        sanitize_bytes(input, Options::default(), Limits::default(), false).unwrap();
    assert_eq!(out, input);
    assert!(summary.encoding.bom);
    assert_eq!(summary.lines, 1);
}

#[test]
fn bom_only_input_roundtrips() {
    let (out, _, _) = sanitize_bytes(
        b"\xEF\xBB\xBF",
        Options::default(),
        Limits::default(),
        false,
    )
    .unwrap();
    assert_eq!(out, b"\xEF\xBB\xBF");
}

#[test]
fn utf16_roundtrip_identity() {
    let mut input = vec![0xFF, 0xFE];
    input.extend("x=1\r\ny 🙂".encode_utf16().flat_map(u16::to_le_bytes));
    let (out, summary) = run_chunked(&input, 3);
    assert_eq!(out, input);
    assert_eq!(summary.encoding.kind, EncodingKind::Utf16Le);
    assert_eq!(summary.lines, 2);
}

#[test]
fn poisoned_after_error_with_complete_prefix() {
    let mut s = Sanitizer::new(
        Options::default(),
        Limits::default(),
        InputEncoding::Auto,
        InvalidUtf8::Error,
        false,
    )
    .unwrap();
    let mut out = Vec::new();
    let e = s.push(b"ok\nbad \xFF tail\n", &mut out).unwrap_err();
    assert_eq!((e.code, e.line), (ErrorCode::InvalidUtf8, Some(2)));
    assert_eq!(
        out, b"ok\n",
        "only complete lines before the failure are emitted"
    );
    assert_eq!(
        s.push(b"more", &mut out).unwrap_err().code,
        ErrorCode::InvalidUtf8
    );
    assert_eq!(s.finish(&mut out).unwrap_err().code, ErrorCode::InvalidUtf8);
    assert_eq!(out, b"ok\n");
}

#[test]
fn line_too_long_emits_nothing_from_that_line() {
    let limits = Limits {
        max_line_bytes: 1024,
        max_total_bytes: None,
    };
    let input = format!("short\n{}\n", "z".repeat(2000));
    let mut s = Sanitizer::new(
        Options::default(),
        limits,
        InputEncoding::Auto,
        InvalidUtf8::Error,
        false,
    )
    .unwrap();
    let mut out = Vec::new();
    let e = s.push(input.as_bytes(), &mut out).unwrap_err();
    assert_eq!((e.code, e.line), (ErrorCode::LineTooLong, Some(2)));
    assert_eq!(out, b"short\n");
}

#[test]
fn max_total_bytes_enforced() {
    let limits = Limits {
        max_line_bytes: 1024,
        max_total_bytes: Some(4),
    };
    let e = sanitize_bytes(b"hello", Options::default(), limits, false).unwrap_err();
    assert_eq!(e.code, ErrorCode::InputTooLarge);
    assert!(sanitize_bytes(b"hell", Options::default(), limits, false).is_ok());
}

#[test]
fn invalid_limits_rejected_at_construction() {
    let bad = Limits {
        max_line_bytes: 10,
        max_total_bytes: None,
    };
    let e = Sanitizer::new(
        Options::default(),
        bad,
        InputEncoding::Auto,
        InvalidUtf8::Error,
        false,
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidOptions);
}

#[test]
fn finish_twice_is_rejected() {
    let mut s = Sanitizer::new(
        Options::default(),
        Limits::default(),
        InputEncoding::Auto,
        InvalidUtf8::Error,
        false,
    )
    .unwrap();
    let mut out = Vec::new();
    s.finish(&mut out).unwrap();
    assert!(s.finish(&mut out).is_err());
    assert!(s.push(b"x", &mut out).is_err());
}

#[test]
fn invalid_utf8_replace_mode_reports_count() {
    let mut s = Sanitizer::new(
        Options::default(),
        Limits::default(),
        InputEncoding::Auto,
        InvalidUtf8::Replace,
        false,
    )
    .unwrap();
    let mut out = Vec::new();
    s.push(b"a\xFFb\n", &mut out).unwrap();
    let summary = s.finish(&mut out).unwrap();
    assert_eq!(out, "a\u{FFFD}b\n".as_bytes());
    assert_eq!(summary.invalid_utf8_replaced, 1);
}

#[test]
fn hidden_census_counts_bidi_invisible_control_lone_cr() {
    let input = "a\u{202E}b\u{200B}c\u{1b}[31m\rnext\u{E0041}\u{7f}".as_bytes();
    let (out, summary, _) =
        sanitize_bytes(input, Options::default(), Limits::default(), false).unwrap();
    assert_eq!(out, input, "census never changes bytes");
    assert_eq!(summary.hidden.bidi, 1);
    assert_eq!(summary.hidden.invisible, 2);
    assert_eq!(summary.hidden.control, 2);
    assert_eq!(summary.hidden.lone_cr, 1);
}
