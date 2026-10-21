use spymonk_redact_core::codec::{Decoder, Encoder};
use spymonk_redact_core::{DetectedEncoding, EncodingKind, ErrorCode, InputEncoding, InvalidUtf8};

type Decoded = (String, DetectedEncoding, u64);

/// Decodes `input` in chunks of `chunk` bytes.
fn decode_chunked(
    enc: InputEncoding,
    invalid: InvalidUtf8,
    input: &[u8],
    chunk: usize,
) -> Result<Decoded, (ErrorCode, String)> {
    let mut d = Decoder::new(enc, invalid);
    let mut out = String::new();
    for c in input.chunks(chunk.max(1)) {
        if let Err(e) = d.decode(c, &mut out) {
            return Err((e.code, out));
        }
    }
    if let Err(e) = d.finish(&mut out) {
        return Err((e.code, out));
    }
    Ok((out, d.detected(), d.invalid_replaced()))
}

/// Decodes whole and byte-by-byte and asserts both agree (chunk independence).
fn decode(
    enc: InputEncoding,
    invalid: InvalidUtf8,
    input: &[u8],
) -> Result<Decoded, (ErrorCode, String)> {
    let whole = decode_chunked(enc, invalid, input, input.len().max(1));
    let bytewise = decode_chunked(enc, invalid, input, 1);
    match (&whole, &bytewise) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "whole vs byte-by-byte"),
        (Err(a), Err(b)) => assert_eq!(a.0, b.0, "error code whole vs byte-by-byte"),
        _ => panic!("whole {whole:?} vs byte-by-byte {bytewise:?}"),
    }
    whole
}

fn auto(input: &[u8]) -> Result<Decoded, (ErrorCode, String)> {
    decode(InputEncoding::Auto, InvalidUtf8::Error, input)
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn utf16be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

#[test]
fn plain_utf8_passes_through() {
    let (s, det, n) = auto("héllo ✓ 🙂\r\n".as_bytes()).unwrap();
    assert_eq!(s, "héllo ✓ 🙂\r\n");
    assert_eq!(
        det,
        DetectedEncoding {
            kind: EncodingKind::Utf8,
            bom: false
        }
    );
    assert_eq!(n, 0);
}

#[test]
fn empty_input_is_utf8_without_bom() {
    let (s, det, _) = auto(b"").unwrap();
    assert_eq!(s, "");
    assert_eq!(
        det,
        DetectedEncoding {
            kind: EncodingKind::Utf8,
            bom: false
        }
    );
}

#[test]
fn utf8_bom_detected_and_stripped() {
    let (s, det, _) = auto(b"\xEF\xBB\xBFpassword=x").unwrap();
    assert_eq!(s, "password=x");
    assert_eq!(
        det,
        DetectedEncoding {
            kind: EncodingKind::Utf8,
            bom: true
        }
    );
}

#[test]
fn utf16le_bom_transcodes_and_roundtrips() {
    let text = "password=fake 🙂\r\nnext";
    let mut input = vec![0xFF, 0xFE];
    input.extend(utf16le(text));
    let (s, det, _) = auto(&input).unwrap();
    assert_eq!(s, text);
    assert_eq!(
        det,
        DetectedEncoding {
            kind: EncodingKind::Utf16Le,
            bom: true
        }
    );

    let enc = Encoder::new(det);
    let mut back = enc.bom().to_vec();
    enc.encode(&s, &mut back);
    assert_eq!(back, input);
}

#[test]
fn utf16be_bom_transcodes_and_roundtrips() {
    let text = "token: fake\n";
    let mut input = vec![0xFE, 0xFF];
    input.extend(utf16be(text));
    let (s, det, _) = auto(&input).unwrap();
    assert_eq!(s, text);
    assert_eq!(
        det,
        DetectedEncoding {
            kind: EncodingKind::Utf16Be,
            bom: true
        }
    );

    let enc = Encoder::new(det);
    let mut back = enc.bom().to_vec();
    enc.encode(&s, &mut back);
    assert_eq!(back, input);
}

#[test]
fn explicit_utf16le_without_bom() {
    let input = utf16le("a=b");
    let (s, det, _) = decode(InputEncoding::Utf16Le, InvalidUtf8::Error, &input).unwrap();
    assert_eq!(s, "a=b");
    assert_eq!(
        det,
        DetectedEncoding {
            kind: EncodingKind::Utf16Le,
            bom: false
        }
    );
}

#[test]
fn utf32le_bom_rejected_unsupported() {
    assert_eq!(
        auto(b"\xFF\xFE\x00\x00a\x00\x00\x00").unwrap_err().0,
        ErrorCode::UnsupportedEncoding
    );
}

#[test]
fn utf32be_bom_rejected_unsupported() {
    assert_eq!(
        auto(b"\x00\x00\xFE\xFF\x00\x00\x00a").unwrap_err().0,
        ErrorCode::UnsupportedEncoding
    );
}

#[test]
fn nul_in_utf8_is_nul_byte_with_valid_prefix() {
    let (code, prefix) = auto(b"hello world, this is text\x00tail").unwrap_err();
    assert_eq!(code, ErrorCode::NulByte);
    assert_eq!(prefix, "hello world, this is text");
}

#[test]
fn ascii_utf16le_without_bom_is_utf16_without_bom() {
    assert_eq!(
        auto(&utf16le("password=fake\n")).unwrap_err().0,
        ErrorCode::Utf16WithoutBom
    );
    assert_eq!(
        auto(&utf16be("password=fake\n")).unwrap_err().0,
        ErrorCode::Utf16WithoutBom
    );
}

#[test]
fn invalid_utf8_error_mode() {
    let (code, prefix) = auto(b"ok \xFF bad").unwrap_err();
    assert_eq!(code, ErrorCode::InvalidUtf8);
    assert_eq!(prefix, "ok ");
}

#[test]
fn invalid_utf8_replace_counts_maximal_subparts() {
    let (s, _, n) = decode(
        InputEncoding::Auto,
        InvalidUtf8::Replace,
        b"a\xF0\x9F\x98b\xFF",
    )
    .unwrap();
    assert_eq!(s, "a\u{FFFD}b\u{FFFD}");
    assert_eq!(n, 2);
}

#[test]
fn truncated_sequence_at_eof() {
    assert_eq!(auto(b"abc\xE2\x82").unwrap_err().0, ErrorCode::InvalidUtf8);
    let (s, _, n) = decode(InputEncoding::Auto, InvalidUtf8::Replace, b"abc\xE2\x82").unwrap();
    assert_eq!((s.as_str(), n), ("abc\u{FFFD}", 1));
}

#[test]
fn split_multibyte_across_chunks() {
    let text = "€🙂ü";
    for chunk in 1..=text.len() {
        let (s, _, _) = decode_chunked(
            InputEncoding::Auto,
            InvalidUtf8::Error,
            text.as_bytes(),
            chunk,
        )
        .unwrap();
        assert_eq!(s, text, "chunk {chunk}");
    }
}

#[test]
fn unpaired_surrogate_is_invalid_utf16() {
    let mut input = vec![0xFF, 0xFE];
    input.extend([0x3D, 0xD8, 0x41, 0x00]); // high surrogate D83D then 'A'
    assert_eq!(auto(&input).unwrap_err().0, ErrorCode::InvalidUtf16);
    let mut lone_low = vec![0xFF, 0xFE];
    lone_low.extend([0x00, 0xDC]);
    assert_eq!(auto(&lone_low).unwrap_err().0, ErrorCode::InvalidUtf16);
    let mut trailing_high = vec![0xFF, 0xFE];
    trailing_high.extend([0x3D, 0xD8]);
    assert_eq!(auto(&trailing_high).unwrap_err().0, ErrorCode::InvalidUtf16);
}

#[test]
fn odd_trailing_byte_is_invalid_utf16() {
    assert_eq!(
        auto(b"\xFF\xFEa\x00b").unwrap_err().0,
        ErrorCode::InvalidUtf16
    );
}

#[test]
fn nul_in_utf16_is_nul_byte() {
    let mut input = vec![0xFF, 0xFE];
    input.extend(utf16le("a\0b"));
    assert_eq!(auto(&input).unwrap_err().0, ErrorCode::NulByte);
}

#[test]
fn short_inputs_that_look_like_bom_prefixes() {
    assert_eq!(auto(b"\xEF").unwrap_err().0, ErrorCode::InvalidUtf8);
    assert_eq!(auto(b"\xFF\xFE").unwrap().0, "");
    assert_eq!(auto(b"\xFE").unwrap_err().0, ErrorCode::InvalidUtf8);
}

#[test]
fn utf8_encoder_writes_bom_only_when_input_had_one() {
    let with = Encoder::new(DetectedEncoding {
        kind: EncodingKind::Utf8,
        bom: true,
    });
    assert_eq!(with.bom(), b"\xEF\xBB\xBF");
    let without = Encoder::new(DetectedEncoding {
        kind: EncodingKind::Utf8,
        bom: false,
    });
    assert_eq!(without.bom(), b"");
    let mut out = Vec::new();
    without.encode("x€", &mut out);
    assert_eq!(out, "x€".as_bytes());
}

/// With UTF-8 requested explicitly, a NUL is binary content; the UTF-16 hint applies only to
/// auto-detection (paste text in the browser is always UTF-8).
#[test]
fn explicit_utf8_leading_nul_is_nul_byte() {
    for input in [&b"\x00abc"[..], b"a\x00bc"] {
        let err = decode(InputEncoding::Utf8, InvalidUtf8::Error, input).unwrap_err();
        assert_eq!(err.0, ErrorCode::NulByte, "{input:?}");
    }
}
