use spymonk_redact_core::framer::{Framer, Separator};
use spymonk_redact_core::{CoreError, ErrorCode};

type Lines = Vec<(String, Separator)>;

fn frame_chunks(chunks: &[&str], max: u32) -> Result<(Lines, u64), (CoreError, Lines)> {
    let mut f = Framer::new(max);
    let mut got: Lines = Vec::new();
    let mut sink = |line: &str, sep: Separator| -> Result<(), CoreError> {
        got.push((line.to_owned(), sep));
        Ok(())
    };
    for c in chunks {
        if let Err(e) = f.push(c, &mut sink) {
            drop(sink);
            return Err((e, got));
        }
    }
    if let Err(e) = f.finish(&mut sink) {
        drop(sink);
        return Err((e, got));
    }
    drop(sink);
    Ok((got, f.lines()))
}

/// Frames `text` whole and one character at a time; both must agree.
fn frame(text: &str) -> (Lines, u64) {
    let whole = frame_chunks(&[text], 1024).unwrap();
    let chars: Vec<String> = text.chars().map(String::from).collect();
    let refs: Vec<&str> = chars.iter().map(String::as_str).collect();
    let split = frame_chunks(&refs, 1024).unwrap();
    assert_eq!(whole, split, "whole vs per-character chunking");
    whole
}

fn l(s: &str, sep: Separator) -> (String, Separator) {
    (s.to_owned(), sep)
}

#[test]
fn lf_crlf_cr_split() {
    let (lines, n) = frame("a\nb\r\nc\rd");
    assert_eq!(
        lines,
        [
            l("a", Separator::Lf),
            l("b", Separator::CrLf),
            l("c", Separator::Cr),
            l("d", Separator::None)
        ]
    );
    assert_eq!(n, 4);
}

#[test]
fn separators_render_verbatim() {
    assert_eq!(Separator::Lf.as_str(), "\n");
    assert_eq!(Separator::CrLf.as_str(), "\r\n");
    assert_eq!(Separator::Cr.as_str(), "\r");
    assert_eq!(Separator::None.as_str(), "");
}

#[test]
fn cr_at_chunk_end_then_lf_is_crlf() {
    let (lines, _) = frame_chunks(&["one\r", "\ntwo"], 1024).unwrap();
    assert_eq!(
        lines,
        [l("one", Separator::CrLf), l("two", Separator::None)]
    );
}

#[test]
fn cr_at_end_of_input_is_lone_cr() {
    let (lines, n) = frame("x\r");
    assert_eq!(lines, [l("x", Separator::Cr)]);
    assert_eq!(n, 1);
}

#[test]
fn double_cr_then_lf() {
    let (lines, _) = frame("a\r\r\nb");
    assert_eq!(
        lines,
        [
            l("a", Separator::Cr),
            l("", Separator::CrLf),
            l("b", Separator::None)
        ]
    );
}

#[test]
fn final_line_without_separator() {
    let (lines, _) = frame("only");
    assert_eq!(lines, [l("only", Separator::None)]);
}

#[test]
fn line_count_rules() {
    assert_eq!(frame("").1, 0);
    assert_eq!(frame("a\n").1, 1);
    assert_eq!(frame("a\n\n").1, 2);
    assert_eq!(frame("a").1, 1);
    assert_eq!(frame("\n").1, 1);
}

#[test]
fn line_at_limit_ok_and_one_over_errors_with_line_number() {
    let at = format!("ok\n{}\n", "x".repeat(1024));
    assert!(frame_chunks(&[&at], 1024).is_ok());

    let over = format!("ok\n{}\nnext", "x".repeat(1025));
    let (err, emitted) = frame_chunks(&[&over], 1024).unwrap_err();
    assert_eq!(err.code, ErrorCode::LineTooLong);
    assert_eq!(err.line, Some(2));
    assert_eq!(emitted, [l("ok", Separator::Lf)]);
}

#[test]
fn limit_enforced_before_separator_arrives() {
    let mut f = Framer::new(1024);
    let mut sink = |_: &str, _: Separator| -> Result<(), CoreError> { Ok(()) };
    let big = "y".repeat(600);
    assert!(f.push(&big, &mut sink).is_ok());
    let err = f.push(&big, &mut sink).unwrap_err();
    assert_eq!((err.code, err.line), (ErrorCode::LineTooLong, Some(1)));
}

#[test]
fn limit_counts_utf8_bytes_not_chars() {
    let line = "é".repeat(513); // 1026 bytes
    let (err, _) = frame_chunks(&[&line], 1024).unwrap_err();
    assert_eq!(err.code, ErrorCode::LineTooLong);
}

#[test]
fn sink_error_propagates() {
    let mut f = Framer::new(1024);
    let mut sink = |_: &str, _: Separator| -> Result<(), CoreError> {
        Err(CoreError::new(ErrorCode::InternalError))
    };
    assert_eq!(
        f.push("a\nb", &mut sink).unwrap_err().code,
        ErrorCode::InternalError
    );
}
