//! Compiles `rules/rules.v1.json` into Rust tables (TRD §8.2). A malformed manifest fails the
//! build, so a binary with a silently reduced rule set cannot be produced.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rules.v1.json");
    println!("cargo:rerun-if-changed={}", manifest.display());

    let bytes = std::fs::read(&manifest)
        .unwrap_or_else(|e| panic!("cannot read rule manifest {}: {e}", manifest.display()));
    let compiled = spymonk_redact_rules::compile(&bytes)
        .unwrap_or_else(|e| panic!("rule manifest rejected: {e}"));

    // OUT_DIR is Cargo's build-script output contract, not user configuration.
    #[allow(clippy::disallowed_methods)]
    let out_dir = std::env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR for build scripts");
    let out = PathBuf::from(out_dir).join("rules_generated.rs");
    std::fs::write(&out, spymonk_redact_rules::generate_rust(&compiled))
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", out.display()));
}
