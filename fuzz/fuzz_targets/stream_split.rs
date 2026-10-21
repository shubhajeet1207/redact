//! TRD §19.4 and I-06: the same input under arbitrary chunking gives the same output, summary,
//! findings, and error as whole-input processing (P-5).
#![no_main]

use libfuzzer_sys::fuzz_target;
use spymonk_redact_core::{InputEncoding, InvalidUtf8, Limits, Options, Sanitizer};

fn run(data: &[u8], mode: InvalidUtf8, widths: &[u8]) -> impl PartialEq + std::fmt::Debug {
    let mut s = Sanitizer::new(
        Options::default(),
        Limits::default(),
        InputEncoding::Auto,
        mode,
        true,
    )
    .expect("default options are valid");
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut k = 0usize;
    while pos < data.len() {
        let width = widths
            .get(k % widths.len().max(1))
            .map_or(data.len(), |w| usize::from(*w & 0x3f) + 1);
        let end = pos.saturating_add(width).min(data.len());
        if let Err(e) = s.push(&data[pos..end], &mut out) {
            return (out, Err(e), Vec::new());
        }
        pos = end;
        k += 1;
    }
    let summary = s.finish(&mut out);
    let ranges = if summary.is_ok() {
        s.take_ranges()
    } else {
        Vec::new()
    };
    (out, summary, ranges)
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let mode = if control & 1 == 1 {
        InvalidUtf8::Replace
    } else {
        InvalidUtf8::Error
    };
    // The first quarter of the remaining bytes chooses chunk widths; the rest is the input.
    let (widths, input) = rest.split_at(rest.len() / 4);
    let whole = run(input, mode, &[]);
    let chunked = run(input, mode, widths);
    assert_eq!(whole, chunked, "P-5: chunking changed the result");
});
