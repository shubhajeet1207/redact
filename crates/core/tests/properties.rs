//! Property tests for the preservation invariants P-1 to P-6 (TRD §7.2, §19.3).
use proptest::prelude::*;
use spymonk_redact_core::rules::PLACEHOLDERS;
use spymonk_redact_core::{
    Finding, InputEncoding, InvalidUtf8, Limits, Options, Sanitizer, Summary, sanitize_bytes,
};

/// Fragments that exercise every detector, separators, quoting, Unicode, and hidden characters.
const FRAGMENTS: &[&str] = &[
    "password=",
    "token: ",
    "\"api_key\": \"",
    "\"",
    "'",
    "=",
    ":",
    ",",
    ";",
    " ",
    "  ",
    "\t",
    "Authorization: Bearer ",
    "Cookie: a=",
    "; b=",
    "Set-Cookie: s=",
    "--password ",
    "DB_PASSWORD=",
    "https://",
    "u:p@",
    "host/",
    "postgres://app:pw@db/x",
    "/home/alex/",
    "/Users/",
    "C:\\Users\\alex\\",
    "alex@example.com",
    "a@b",
    ".com",
    "10.0.0.8",
    "192.168.1.1",
    ":5432",
    "fd12:3456::1",
    "[",
    "]",
    "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "AKIAFAKEFAKEFAKE0000",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
    "-----BEGIN PRIVATE KEY-----",
    "-----END PRIVATE KEY-----",
    "MIIEvQIBADANBg",
    "\\n",
    "\n",
    "\r\n",
    "\r",
    "[REDACTED]",
    "[EMAIL REDACTED]",
    "[PRIVATE KEY REDACTED]",
    "null",
    "value",
    "x",
    "🙂",
    "é",
    "e\u{301}",
    "\u{202E}",
    "\u{200B}",
    "\u{1b}[31m",
    "\u{E0041}",
    "中文",
    "∑",
];

/// 512 cases per property, or `PROPTEST_CASES` for longer local and scheduled CI runs.
#[allow(clippy::disallowed_methods)] // Test-only: selects the case count for long runs.
fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

/// Marks inserted placeholders in residue checks; never produced by the fragments.
const MARK: char = '\u{F8FF}';

fn text() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(FRAGMENTS), 0..48).prop_map(|v| v.concat())
}

fn opts() -> impl Strategy<Value = Options> {
    (any::<bool>(), any::<bool>()).prop_map(|(email, private_ip)| Options { email, private_ip })
}

fn sanitize(input: &str, o: Options) -> (String, Summary, Vec<Finding>) {
    let (out, s, f) = sanitize_bytes(input.as_bytes(), o, Limits::default(), true).unwrap();
    (String::from_utf8(out).unwrap(), s, f)
}

/// Line contents without separators (LF, CRLF, lone CR); a final empty remainder is not a line.
fn line_contents(s: &str) -> Vec<&str> {
    let mut v = Vec::new();
    let b = s.as_bytes();
    let (mut start, mut i) = (0usize, 0usize);
    while i < b.len() {
        match b[i] {
            b'\r' if b.get(i + 1) == Some(&b'\n') => {
                v.push(&s[start..i]);
                i += 2;
                start = i;
            }
            b'\r' | b'\n' => {
                v.push(&s[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < b.len() {
        v.push(&s[start..]);
    }
    v
}

fn separators(s: &str) -> Vec<&'static str> {
    let b = s.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1)) {
            (b'\r', Some(b'\n')) => {
                v.push("\r\n");
                i += 2;
            }
            (b'\r', _) => {
                v.push("\r");
                i += 1;
            }
            (b'\n', _) => {
                v.push("\n");
                i += 1;
            }
            _ => i += 1,
        }
    }
    v
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), .. ProptestConfig::default() })]

    /// P-1: every output byte outside an inserted placeholder comes from the same input line, in
    /// order. Private-key continuation lines are removed without a placeholder, so alignment is
    /// checked per line, which the identical separator sequence (P-2) makes well defined.
    #[test]
    fn residue_equality(input in text(), o in opts()) {
        let (out, _, findings) = sanitize(&input, o);
        let mut marked = String::new();
        let mut pos = 0usize;
        for f in &findings {
            marked.push_str(&out[pos..f.start as usize]);
            marked.push(MARK);
            pos = f.end as usize;
        }
        marked.push_str(&out[pos..]);
        let in_lines = line_contents(&input);
        let out_lines = line_contents(&marked);
        prop_assert!(out_lines.len() == in_lines.len() || out_lines.len() + 1 == in_lines.len());
        for (inl, outl) in in_lines.iter().zip(&out_lines) {
            let mut cursor = 0usize;
            for seg in outl.split(MARK) {
                let found = inl[cursor..].find(seg);
                prop_assert!(found.is_some(), "segment {:?} not in input line {:?}", seg, inl);
                cursor += found.unwrap() + seg.len();
            }
        }
    }

    /// P-2: the separator sequence is identical, so every terminated line keeps its number. Only a
    /// final unterminated line consisting entirely of private-key body can disappear.
    #[test]
    fn line_structure_preserved(input in text(), o in opts()) {
        let (out, _, _) = sanitize(&input, o);
        prop_assert_eq!(separators(&out), separators(&input));
        let (a, b) = (line_contents(&input).len(), line_contents(&out).len());
        prop_assert!(b == a || b + 1 == a);
    }

    /// P-3: identical input and options give identical output.
    #[test]
    fn deterministic(input in text(), o in opts()) {
        prop_assert_eq!(sanitize(&input, o), sanitize(&input, o));
    }

    /// P-4: processing the output again changes nothing.
    #[test]
    fn idempotence(input in text(), o in opts()) {
        let (once, _, _) = sanitize(&input, o);
        let (twice, s, _) = sanitize(&once, o);
        prop_assert_eq!(&twice, &once);
        prop_assert_eq!(s.replacements, 0);
    }

    /// P-5: output and summary do not depend on chunking.
    #[test]
    fn chunk_independence(input in text(), o in opts(), sizes in prop::collection::vec(1usize..64, 1..16)) {
        let whole = sanitize_bytes(input.as_bytes(), o, Limits::default(), false).unwrap();
        let mut s = Sanitizer::new(o, Limits::default(), InputEncoding::Auto, InvalidUtf8::Error, false).unwrap();
        let mut out = Vec::new();
        let bytes = input.as_bytes();
        let (mut i, mut k) = (0usize, 0usize);
        while i < bytes.len() {
            let n = sizes[k % sizes.len()].min(bytes.len() - i);
            s.push(&bytes[i..i + n], &mut out).unwrap();
            i += n;
            k += 1;
        }
        let summary = s.finish(&mut out).unwrap();
        prop_assert_eq!(out, whole.0);
        prop_assert_eq!(summary, whole.1);
    }

    /// P-6: counts are consistent with the placeholders actually inserted.
    #[test]
    fn counts_consistent(input in text(), o in opts()) {
        let (_, s, findings) = sanitize(&input, o);
        prop_assert_eq!(s.by_rule.iter().sum::<u64>(), s.replacements);
        prop_assert_eq!(findings.len() as u64, s.replacements);
    }

    /// Findings are ordered, disjoint, and each covers exactly one reserved placeholder.
    #[test]
    fn ranges_point_at_placeholders(input in text(), o in opts()) {
        let (out, _, findings) = sanitize(&input, o);
        let mut last_end = 0u64;
        for f in &findings {
            prop_assert!(f.start >= last_end && f.end > f.start);
            let text = &out[f.start as usize..f.end as usize];
            prop_assert!(PLACEHOLDERS.contains(&text), "{:?} is not a placeholder", text);
            last_end = f.end;
        }
    }

    /// Arbitrary Unicode never panics; the engine either succeeds or reports a fixed error.
    #[test]
    fn no_panic_on_unicode(input in any::<String>(), o in opts()) {
        let _ = sanitize_bytes(input.as_bytes(), o, Limits::default(), true);
    }

    /// Arbitrary bytes never panic, in either invalid-UTF-8 mode.
    #[test]
    fn no_panic_on_bytes(input in prop::collection::vec(any::<u8>(), 0..512), replace in any::<bool>()) {
        let mode = if replace { InvalidUtf8::Replace } else { InvalidUtf8::Error };
        let mut s = Sanitizer::new(Options::default(), Limits::default(), InputEncoding::Auto, mode, true).unwrap();
        let mut out = Vec::new();
        if s.push(&input, &mut out).is_ok() {
            let _ = s.finish(&mut out);
        }
    }

    /// Synthetic secrets placed in supported contexts never survive, whatever surrounds them.
    #[test]
    fn canaries_never_survive(
        noise in prop::collection::vec(text(), 4),
        which in prop::collection::vec(0usize..6, 1..4),
    ) {
        const CONTEXTS: [&str; 6] = [
            "password=CANARYzq1",
            "Authorization: Bearer CANARYzq2",
            "https://user:CANARYzq3@host.example/x",
            "ghp_CANARYzq4aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "\"client_secret\": \"CANARYzq5\"",
            "Cookie: session=CANARYzq6",
        ];
        let mut input = String::new();
        for (i, w) in which.iter().enumerate() {
            input.push_str(&noise[i % noise.len()]);
            input.push('\n');
            input.push_str(CONTEXTS[*w]);
            input.push('\n');
        }
        let (out, _, _) = sanitize(&input, Options::default());
        prop_assert!(!out.contains("CANARYzq"), "canary survived in {:?}", out);
    }
}
