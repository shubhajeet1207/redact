//! TRD §19.4: arbitrary bytes and options. Oracles: no panic, P-4 idempotence, P-6 counts, and
//! every finding points at a reserved placeholder.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spymonk_redact_core::rules::PLACEHOLDERS;
use spymonk_redact_core::{Limits, Options, sanitize_bytes};

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

fuzz_target!(|data: &[u8]| {
    let Some((&flags, input)) = data.split_first() else {
        return;
    };
    let options = Options {
        email: flags & 1 != 0,
        private_ip: flags & 2 != 0,
    };
    let Ok((out, summary, findings)) = sanitize_bytes(input, options, Limits::default(), true)
    else {
        return;
    };

    assert_eq!(summary.by_rule.iter().sum::<u64>(), summary.replacements);
    assert_eq!(findings.len() as u64, summary.replacements);

    // Findings are UTF-8 offsets into the text after any byte-order mark.
    if let Ok(text) = std::str::from_utf8(out.strip_prefix(UTF8_BOM).unwrap_or(&out)) {
        let mut last = 0;
        for f in &findings {
            assert!(f.start >= last && f.end > f.start);
            let range = text.get(f.start as usize..f.end as usize);
            assert!(range.is_some_and(|p| PLACEHOLDERS.contains(&p)), "{f:?}");
            last = f.end;
        }
    }

    // Placeholders can make a line longer than the input limit, so the second run allows more.
    let wide = Limits {
        max_line_bytes: 67_108_864,
        max_total_bytes: None,
    };
    let (again, second, _) =
        sanitize_bytes(&out, options, wide, false).expect("sanitized output is valid input");
    assert_eq!(again, out, "P-4: a second run changed the output");
    assert_eq!(second.replacements, 0);
});
