//! Fast regression gate for inputs that historically cause quadratic behavior in naïve scanners.
//!
//! This is deliberately a debug-build test: a 2 MiB pathological line must finish inside five
//! seconds before it can become an accidental hours-long release-build regression.

use std::time::{Duration, Instant};

use spymonk_redact_core::{Limits, Options, sanitize_bytes};

const TWO_MIB: usize = 2 * 1024 * 1024;
const LIMIT: Duration = Duration::from_secs(5);

fn full_line(seed: &str) -> String {
    let repeats = TWO_MIB / seed.len() + 1;
    let mut input = seed.repeat(repeats);
    input.truncate(TWO_MIB);
    input
}

fn wide_limits() -> Limits {
    Limits {
        max_line_bytes: 67_108_864,
        max_total_bytes: None,
    }
}

fn assert_finishes(name: &str, input: String) {
    let started = Instant::now();
    let result = sanitize_bytes(input.as_bytes(), Options::default(), wide_limits(), false);
    let elapsed = started.elapsed();
    assert!(result.is_ok(), "{name} failed unexpectedly: {result:?}");
    assert!(
        elapsed < LIMIT,
        "{name} took {elapsed:?}; expected less than {LIMIT:?} for a 2 MiB adversarial line"
    );
}

#[test]
fn families_complete_in_bounded_time() {
    let mut unterminated_quote = String::from("password=\"");
    unterminated_quote.push_str(&"a".repeat(TWO_MIB - unterminated_quote.len()));

    for (name, input) in [
        ("repeated-url-schemes", full_line("://")),
        ("named-value-chains", full_line("password=password=")),
        ("at-sign-flood", full_line("@")),
        ("unterminated-quote", unterminated_quote),
        ("home-path-flood", full_line("/home/")),
        ("digit-dot-flood", full_line("10.0.0.")),
        ("jwt-prefix-flood", full_line("eyJ")),
        (
            "begin-armor-flood",
            full_line("-----BEGIN PRIVATE KEY-----"),
        ),
    ] {
        assert_finishes(name, input);
    }
}

/// Best of three runs, so a scheduler hiccup cannot fail the ratio check below.
fn best_time(input: &str) -> Duration {
    (0..3)
        .map(|_| {
            let started = Instant::now();
            let result = sanitize_bytes(input.as_bytes(), Options::default(), wide_limits(), false);
            let elapsed = started.elapsed();
            assert!(result.is_ok(), "sanitize failed: {result:?}");
            elapsed
        })
        .min()
        .unwrap_or_default()
}

fn line_of(seed: &str, bytes: usize) -> String {
    let mut input = seed.repeat(bytes / seed.len() + 1);
    input.truncate(bytes);
    input
}

/// TRD §7.4 and §19.9: time grows linearly with line length. Quadrupling a line built from many
/// values must not cost more than about eight times as much (a quadratic scan costs sixteen).
#[test]
fn many_values_on_one_line_scale_linearly() {
    const SMALL: usize = 128 * 1024;
    let floor = Duration::from_millis(20);
    for (name, seed) in [
        ("quoted-values", "\"token\": \"x\", "),
        ("unquoted-values", "password=x "),
        ("authorization-headers", "Authorization: Bearer x "),
        ("cookie-pairs", "Cookie: a=b; "),
        ("url-credentials", "https://u:p@h/ "),
        ("home-paths", "/home/alex/ "),
        ("emails", "a@b.co "),
        ("mixed-values-and-paths", "password=x /home/alex/f "),
    ] {
        let small = best_time(&line_of(seed, SMALL));
        let large = best_time(&line_of(seed, SMALL * 4));
        assert!(
            large <= small.max(floor) * 8,
            "{name}: {small:?} at 128 KiB but {large:?} at 512 KiB (super-linear)"
        );
    }
}
