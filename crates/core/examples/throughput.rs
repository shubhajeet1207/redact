//! Throughput check for the TRD §19.9 gates on the development machine.
//!
//! Run with `cargo run --release -p spymonk-redact-core --example throughput`. It reports MiB/s
//! for the benign corpus (gate: at least 100), a secret-dense log (gate: at least 30), and the
//! adversarial families (gate: at least 25% of dense, and linear in line length).

use std::time::{Duration, Instant};

use spymonk_redact_core::{Limits, Options, sanitize_bytes};

const TARGET: usize = 64 * 1024 * 1024;

fn grow(seed: &str, bytes: usize) -> String {
    let mut s = seed.repeat(bytes / seed.len().max(1) + 1);
    s.truncate(bytes);
    s
}

fn benign() -> String {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/benign");
    let mut seed = String::new();
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .expect("fixtures/benign exists")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    paths.sort();
    for p in paths {
        seed.push_str(&std::fs::read_to_string(p).expect("benign log is UTF-8"));
        if !seed.ends_with('\n') {
            seed.push('\n');
        }
    }
    grow(&seed, TARGET)
}

fn dense() -> String {
    let seed = "2026-10-21T09:00:00Z INFO login user=alex@example.com password=fake-pass-1 \
                token=fake-token-2 path=/home/alex/app\n\
                2026-10-21T09:00:01Z DEBUG Authorization: Bearer fake-bearer-3 Cookie: sid=fake4; \
                theme=dark url=postgres://app:fake5@db.internal/x\n\
                {\"api_key\": \"fake-key-6\", \"client_secret\": \"fake-7\", \"host\": \"10.0.0.8\"}\n";
    grow(seed, TARGET)
}

fn limits() -> Limits {
    Limits {
        max_line_bytes: 67_108_864,
        max_total_bytes: None,
    }
}

fn best_of(input: &str, runs: usize) -> Duration {
    (0..runs)
        .map(|_| {
            let t = Instant::now();
            sanitize_bytes(input.as_bytes(), Options::default(), limits(), false)
                .expect("sanitize succeeds");
            t.elapsed()
        })
        .min()
        .unwrap_or_default()
}

fn mib_s(bytes: usize, d: Duration) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / d.as_secs_f64()
}

fn main() {
    let b = benign();
    let d = dense();
    let benign_rate = mib_s(b.len(), best_of(&b, 3));
    let dense_rate = mib_s(d.len(), best_of(&d, 3));
    println!("benign      {benign_rate:8.1} MiB/s  (gate >= 100)");
    println!("dense       {dense_rate:8.1} MiB/s  (gate >= 30)");

    let small = 4 * 1024 * 1024;
    for (name, seed) in [
        ("quoted-values", "\"token\": \"x\", "),
        ("unquoted-values", "password=x "),
        ("auth-headers", "Authorization: Bearer x "),
        ("cookie-pairs", "Cookie: a=b;"),
        ("url-schemes", "://"),
        ("named-chains", "password=password="),
        ("at-signs", "@"),
        ("home-paths", "/home/"),
        ("digit-dots", "10.0.0."),
        ("begin-armor", "-----BEGIN PRIVATE KEY-----"),
    ] {
        let a = grow(seed, small);
        let z = grow(seed, small * 4);
        let ta = best_of(&a, 3);
        let tz = best_of(&z, 3);
        let per_byte_ratio =
            (tz.as_secs_f64() / z.len() as f64) / (ta.as_secs_f64() / a.len() as f64);
        println!(
            "{name:<14}{:8.1} MiB/s at 16 MiB, time/byte 16 MiB vs 4 MiB = {per_byte_ratio:.2}",
            mib_s(z.len(), tz)
        );
    }
}
