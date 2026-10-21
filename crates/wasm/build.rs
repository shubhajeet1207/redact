//! TRD §11.2: the WebAssembly module declares a maximum linear memory of 512 MiB, so even a
//! defect cannot grow the worker without bound. A link argument from the build script survives a
//! caller-supplied `RUSTFLAGS`, which would replace config-file flags.

fn main() {
    // Build scripts receive the target through Cargo's environment; reading it is the only way.
    #[allow(clippy::disallowed_methods)]
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if arch == "wasm32" {
        println!("cargo:rustc-link-arg-cdylib=--max-memory=536870912");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
