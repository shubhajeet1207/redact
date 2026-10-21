# Installation and verification

> **Release status: not available.** SpyMonk Redact is under development: the detection engine and the browser playground exist in source form, and the command-line interface does not exist yet. There is no published CLI, browser playground, Python package, standalone archive, container image, release signature, checksum, or verification artifact to install today.

Do not run `pip install spymonk-redact`, copy commands from older design documents, or rely on an identically named third-party package. The public package and registry identities have not yet been reserved or verified.

## Planned installation channels

After implementation and the release gates in the [technical requirements](../TRD.md) have passed, this page will contain exact, tested commands for the following channels:

| Channel | Intended use | Planned form |
| --- | --- | --- |
| **pip / pipx / uv** | Developer machines and automation | Platform wheel containing the native `spymonk-redact` binary with a minimal Python launcher. |
| **Standalone archive** | Environments without Python package tooling | Signed archives for Windows, macOS, and Linux on x86-64 and ARM64. |
| **Container image** | Controlled CI or container environments | A published OCI image with a pinned digest. |
| **Browser playground** | Pasted text and locally chosen files | A static web application that processes content in the browser after initial load. |

The CLI and browser are designed to use the same compiled rule set and produce identical output for the same input and options. This is a design requirement, not a current release claim.

## What a release must provide

Every published artifact is planned to include:

- a cryptographic signature and published checksum;
- Sigstore-signed provenance and a software bill of materials (SBOM);
- documented verification commands for the artifact and its provenance;
- a versioned rule-set identifier and hash visible through the CLI;
- clean-environment installation and regression evidence for each supported platform and channel.

The static website release is also planned to publish its asset hashes and an offline bundle. It will not use cookies, analytics, third-party resources, or client-side persistence.

## Before using a future release

When real artifacts are available, use this checklist:

1. Install only from the official project links published in a GitHub release and on this page.
2. Check the release version, checksum, signature, and provenance before relying on an artifact.
3. Run `spymonk-redact --version` and confirm its build and rule-set identifiers match the release notes.
4. Start with a synthetic sample rather than production logs.
5. Review all sanitized output before sharing, and rotate any credential that may already have been exposed.

## Building from source

The engine and the browser playground build from source. You need the Rust toolchain pinned in `rust-toolchain.toml` (it installs automatically through `rustup`), `wasm-bindgen-cli` 0.2.129 (`cargo install wasm-bindgen-cli --version 0.2.129 --locked`), and Node.js 22.13 or later.

```sh
cargo test --workspace --locked                 # engine, rule compiler, WebAssembly adapter
cd web
npm ci                                          # install scripts are disabled by web/.npmrc
npm run build                                   # engine to WebAssembly, type checks, bundle, bundle verification
npm run serve                                   # http://127.0.0.1:4173/ with the production headers
```

A source build is for development and review. It is not a signed release, and its output carries the commit it was built from rather than a release version.

For product behavior, planned rule coverage, and current limitations, see the [PRD](../PRD.md). For the proposed packaging, provenance, and verification controls, see the [TRD](../TRD.md).
