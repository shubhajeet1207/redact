# M2–M5: CLI, Packaging, Evidence, and Release Preparation — Implementation Plan

**Goal:** Ship the `spymonk-redact` command-line interface of TRD §9 with its tests (§19.6, §19.7), the Python launcher and unsigned build definitions (M2), the evidence and documentation tooling of M4, and the release workflows of M5, stopping short of publication, which stays an owner action.

**Architecture:** `crates/cli` is a thin adapter over `spymonk-redact-core`: it parses arguments with `lexopt`, opens input and output by handle, streams 64 KiB chunks through `Sanitizer`, renders for terminals, writes reports, and hardens the process before reading input. Platform code (`harden/`, `signals.rs`, Windows file identity) is the only place `unsafe` is allowed, each block with a safety comment. A `build.rs` generates the rule catalog for `--list-rules` from the manifest and records build identity.

**Tech Stack:** Rust 1.99.1; `lexopt` 0.3.2; `libc` 0.2.190 (Unix); `seccompiler` 0.5.0 (Linux); `windows-sys` 0.61.2 (Windows); maturin 1.15.0 (`bindings = "bin"`); GitHub Actions.

**Spec:** [TRD v2.1](../TRD.md) §5.4, §5.5, §9, §14, §19.6, §19.7, §21; [PRD v1.1](../PRD.md).

## Global Constraints

- Usage errors exit 2 and never echo the user-supplied value; non-UTF-8 arguments are rejected with a fixed message.
- Messages and reports never contain input content, file names, paths, argument values, or system error text.
- No environment configuration, no network, no process creation; `clippy.toml` bans stay in force.
- Atomic output: same-file and non-regular-target refusals before reading input; create-new temporary file (`0600`, no-follow on Unix); flush, sync, rename, directory sync; temporary file removed on every failure path.
- Exit codes: 0 success, 1 failure, 2 usage, 130 SIGINT or Ctrl+C, 143 SIGTERM, 141 broken pipe (Unix).
- Fixed notice on every successful run; JSON on standard error is exactly one document.
- Dependencies pinned, each release at least 14 days old; no `ctrlc` (see the ledger ruling).

## Review Focus

1. A failure after output began must leave only complete lines on standard output, and no file at the `--output` target.
2. Different spellings of the same file, including hard links, must be refused as `OUTPUT_IS_INPUT`.
3. Reports and errors must never contain an input canary or the input path.
4. Terminal rendering must neutralize escape sequences while redirected output stays byte-exact.
5. CLI output must equal the WebAssembly paths byte for byte (parity).

---

### Task 1: CLI crate, arguments, and information commands

**Files:** `crates/cli/{Cargo.toml,build.rs,src/main.rs,src/args.rs,src/catalog.rs}`; tests `crates/cli/tests/args.rs`.

- [ ] Tests: `--help`, `--version` (tool, rule version and hash, commit, target, build date), `--list-rules` text and JSON, unknown option and bad value exit 2 without echoing the value, two operands exit 2, `--` allows a leading-dash file name, non-UTF-8 argument rejected.

### Task 2: Input, streaming, and standard output

**Files:** `src/io.rs`, `src/run.rs`; tests `crates/cli/tests/io.rs`.

- [ ] Tests: stdin, file, `-`; empty input; directory and missing file give `INPUT_READ_FAILED` without the path; encodings and limits as in §19.6; failure mid-stream leaves complete lines only; interactive stdin with no file exits 2 (Unix PTY test skipped where unavailable).

### Task 3: Atomic output and reports

**Files:** `src/atomic.rs`, `src/report.rs`, `schemas/report.v1.schema.json`; tests `crates/cli/tests/output.rs`, `crates/cli/tests/report.rs`.

- [ ] Tests: `--output` success with empty stdout; same path, hard link, and `a/../file` refusals; symbolic-link refusal (Unix); missing directory gives `OUTPUT_WRITE_FAILED`; failure leaves the target untouched and no temporary file; text and JSON reports match §9.6; every failure code's report validates against the schema; `--report-file` is atomic; canaries never appear in stderr or reports.

### Task 4: Rendering, signals, broken pipe, hardening

**Files:** `src/render.rs`, `src/signals.rs`, `src/harden/{mod.rs,unix.rs,linux.rs,windows.rs}`; tests `crates/cli/tests/platform.rs`.

- [ ] Tests: `--escape-controls always` marks every hidden class and lone CR; `never` and redirected `auto` are byte-exact; broken pipe exits 141 (Unix); SIGINT and SIGTERM exit 130 and 143 with no temporary file (Unix); core-dump limits and the seccomp probe (Linux, behind the `sandbox-probe` feature).

### Task 5: Parity

**Files:** `crates/cli/tests/parity.rs`.

- [ ] Every fixture and generated inputs give identical bytes from the CLI, `sanitize_bytes`, the WebAssembly streaming job, and paste mode (UTF-8 inputs up to 1 MiB).

### Task 6: Python launcher and package builds (unsigned)

**Files:** `python/{pyproject.toml,README.md,spymonk_redact/__init__.py,spymonk_redact/__main__.py}`, `packaging/Containerfile`, `tools/package-archive.sh`, `tools/check-imports.sh`, `tools/check-no-network.sh`, `.github/workflows/build-reusable.yml`.

- [ ] A locally built wheel installs and runs both `spymonk-redact` and `python -m spymonk_redact`, passing exit codes through.

### Task 7: Release workflows, evidence, and documentation

**Files:** `.github/workflows/{release.yml,scorecard.yml}`, `.github/allowed_signers`, `evidence.yml`, `docs/compliance/*`, `docs/privacy.md`, `docs/support.md`, `docs/installation/README.md`, `SECURITY.md`, `TRD.md`.

- [ ] Workflows lint as YAML and pin every action by commit SHA; evidence lists every §21.2 gate with its current status and source; documentation states only what exists.
