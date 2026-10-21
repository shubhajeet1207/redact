//! TRD §19.4: BOMs, UTF-16, and invalid sequences. Oracles: no panic, and byte-by-byte decoding
//! gives the same text, error, and detected encoding as decoding everything at once.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spymonk_redact_core::codec::Decoder;
use spymonk_redact_core::{InputEncoding, InvalidUtf8};

fn decode(data: &[u8], invalid: InvalidUtf8, bytewise: bool) -> impl PartialEq + std::fmt::Debug {
    let mut decoder = Decoder::new(InputEncoding::Auto, invalid);
    let mut text = String::new();
    let mut error = None;
    if bytewise {
        for byte in data {
            if let Err(e) = decoder.decode(core::slice::from_ref(byte), &mut text) {
                error = Some(e.code);
                break;
            }
        }
    } else if let Err(e) = decoder.decode(data, &mut text) {
        error = Some(e.code);
    }
    if error.is_none()
        && let Err(e) = decoder.finish(&mut text)
    {
        error = Some(e.code);
    }
    (text, error, decoder.detected(), decoder.invalid_replaced())
}

fuzz_target!(|data: &[u8]| {
    for invalid in [InvalidUtf8::Error, InvalidUtf8::Replace] {
        let whole = decode(data, invalid, false);
        let bytewise = decode(data, invalid, true);
        assert_eq!(whole, bytewise);
    }
});
