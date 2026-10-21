//! TRD §19.4: the build-time manifest validator on arbitrary JSON. Oracle: it returns an error
//! or a compiled rule set, never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(compiled) = spymonk_redact_rules::compile(data) {
        let _ = spymonk_redact_rules::generate_rust(&compiled);
        let _ = spymonk_redact_rules::generate_markdown(&compiled);
    }
});
