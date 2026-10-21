//! TRD §19.4: line framing. Oracles: no panic; character-by-character framing gives the same
//! lines, separators, and errors as framing the whole text; joining lines and separators
//! reproduces the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spymonk_redact_core::framer::Framer;

const MAX_LINE: u32 = 1024;

fn frame(text: &str, per_char: bool) -> (Vec<(String, &'static str)>, bool) {
    let mut framer = Framer::new(MAX_LINE);
    let mut lines = Vec::new();
    let mut sink = |line: &str, sep: spymonk_redact_core::framer::Separator| {
        lines.push((line.to_owned(), sep.as_str()));
        Ok(())
    };
    let mut failed = false;
    if per_char {
        let mut buf = [0u8; 4];
        for c in text.chars() {
            if framer.push(c.encode_utf8(&mut buf), &mut sink).is_err() {
                failed = true;
                break;
            }
        }
    } else {
        failed = framer.push(text, &mut sink).is_err();
    }
    if !failed {
        failed = framer.finish(&mut sink).is_err();
    }
    (lines, failed)
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let whole = frame(&text, false);
    assert_eq!(whole, frame(&text, true));
    if !whole.1 {
        let joined: String = whole.0.iter().map(|(l, s)| format!("{l}{s}")).collect();
        assert_eq!(joined, text);
    }
});
