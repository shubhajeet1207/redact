# SpyMonk Redact Technical Requirements Document

| Field | Value |
| --- | --- |
| Version | 2.2 (implementation alignment of v2.0; v2.0 replaced [TRD v1.0](archive/TRD-v1.0.md)) |
| Date | 21 October 2026 |
| Product baseline | [PRD v1.1](PRD.md) and [PRD review](PRD_REVIEW.md) (findings PRV-01 to PRV-27) |
| Status | PRD v1.1 and ADR-01 approved by the owner on 21 October 2026. Milestones M0 to M3 are implemented, and the M4 and M5 workflows, evidence register, and runbook exist; v2.1 and v2.2 record the design rulings made while implementing them (see the revision history). Publication remains an owner action. |
| Intended readers | Engineers implementing the engine, CLI, browser app, tests, and release pipeline; security reviewers; auditors checking compliance evidence |

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as described in RFC 2119 and RFC 8174. Statements in this document describe required behavior and planned verification. None is a claim that a built product has passed a test. Every numeric performance figure is a release gate to be measured, not a measured result.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 2.0 | 21 October 2026 | Fresh design replacing TRD v1.0. |
| 2.2 | 22 October 2026 | M2 implementation rulings: own async-signal-safe handlers instead of `ctrlc`, so SIGINT and SIGTERM keep distinct exit codes (§9.4, §14.3); no environment reads at all, including `TERM` (§9.8); display escaping applies to standard output only (§9.5); report fields that need a summary are `null` after an early failure, `sandbox` adds `process-mitigations`, and the text report adds error and warning lines (§9.6); FIFOs are opened non-blocking so they can be rejected (§9.2); temporary names use `/dev/urandom` or `BCryptGenRandom` (§9.3); file opens are confined to `io.rs`, `atomic.rs`, and `osrand.rs` by review, because Clippy cannot scope a ban to modules (§9.8); the seccomp effect test uses the `sandbox-probe` feature (§19.6); packaging specifics (§9.9, §14.2); `pyproject.toml` sits at the workspace root, because maturin packages only files beneath it and the source distribution must carry the rule manifest (§9.9). |
| 2.1 | 21 October 2026 | M3 implementation rulings: one Trusted Types policy that accepts only the hashed worker URL, because the `Worker` constructor is a Trusted Types sink (§10.6, §11.3); separate paste and file workers from the same script (§10.5); 1 MiB `File.slice()` reads (§10.4); static copy in `index.html`, runtime text in `strings.ts` (§10.1); the product mark is the favicon (§10.1); toolchain and npm settings (§4); `security.txt` `Canonical` once the domain exists (§11.3). M1 implementation rulings: UTF-16 detection without look-ahead (§5.2); SR-002 scheme list and fail-closed unknown schemes (§6.3); URL extent ends at backticks and controls (§6.4); private-key blocks own their byte ranges, and a removed body line after a lone CR keeps its placeholder (§6.9); headers that follow a cookie field are parsed on their own (§6.10); per-line fixed point that makes idempotence hold by construction, with a fail-closed cap (§7.1); P-2 stated as an identical separator sequence (§7.2); warning `UNSTABLE_LINE_REDACTED` (§5.1, §7.1). |

## Contents

1. Outcome and scope
2. Architecture decisions
3. System context, components, and trust boundaries
4. Repository, toolchain, and build structure
5. Engine design
6. Detection rules
7. Matching, overlap resolution, and preservation
8. Rule manifest, compilation, and governance
9. CLI design
10. Browser application design
11. Security architecture
12. Integrity architecture
13. Scalability architecture
14. Supply chain and release integrity
15. Project security and governance
16. Vulnerability management and lifecycle
17. Compliance mapping
18. Privacy and legal
19. Verification plan
20. Supportability without telemetry
21. Delivery milestones and release gates
22. Traceability
23. Owner decisions and assumptions
24. References

## 1. Outcome and scope

Build one deterministic sanitization engine and deliver it through two surfaces:

- **CLI:** `spymonk-redact`, installable with pip, pipx, or uv, as standalone archives, and as a container image.
- **Static browser application:** paste mode and file mode.

Every surface runs the same compiled engine and the same compiled rule set. All processing happens on the user's device. There is no API server, database, account system, cloud model, telemetry, update check, or background service. The website loads static assets once at start-up; after that, processing makes no network requests.

The design closes every finding in the PRD review. §22 maps each finding and each PRD requirement to the sections that satisfy it and to the test that proves it.

## 2. Architecture decisions

| ID | Decision | Consequence |
| --- | --- | --- |
| ADR-01 | One detection engine, written in Rust: the `spymonk-redact-core` crate, `no_std` with `alloc`, `#![forbid(unsafe_code)]`. It is compiled natively for the CLI and to WebAssembly for the browser. | Parity holds by construction (PRV-07). Memory safety in the processing path. Without `std`, the engine has no access to files, network, processes, clocks, or environment. A toolchain matrix is needed for native builds. |
| ADR-02 | Detectors are single-pass scanners with a monotonic cursor. Literal triggers are located with `memchr` and `aho-corasick`. No backtracking regular-expression engine appears anywhere in the processing path. | Linear worst-case time for every input (PRV-03). Grammars are explicit code rather than regex dialects. More code per rule, offset by data-driven detector types. |
| ADR-03 | The rule manifest is validated and compiled into the engine at build time. Its SHA-256 is embedded. There is no runtime rule loading. | No tampering surface and no parse cost at run time. Documentation and `--list-rules` are generated from the same tables (PRV-11). |
| ADR-04 | Processing streams in lines with bounded state. Whole-text APIs are thin wrappers over the streaming API. | Any input size in bounded memory (PRV-01). Chunk independence is a testable invariant. |
| ADR-05 | The CLI is a Rust binary. It is published as platform wheels built with maturin (`bindings = "bin"`) together with a dependency-free Python launcher, as standalone archives, and as an OCI image. | `pip install spymonk-redact` works with no Python code on the processing path (PRV-23). The same binary serves every channel. This is the distribution model used by ruff and uv. |
| ADR-06 | The browser app uses strict-mode TypeScript, Vite, and no UI framework. One module Web Worker hosts the WebAssembly engine. The WebAssembly bytes are embedded in the worker bundle and instantiated from memory. | The main page needs neither `connect-src` nor `'wasm-unsafe-eval'`. Only the worker's policy allows WebAssembly compilation (PRV-16). |
| ADR-07 | Standard output carries sanitized content only. Diagnostics, the notice, and reports go to standard error or a report file. The JSON report schema is versioned. | Pipelines remain correct. Automation gets a stable contract (PRV-04). |
| ADR-08 | File output is atomic: a temporary file in the same directory, synced, then renamed. Output that resolves to the input file is refused, using file identity rather than path text. | Output is complete or absent. The input can never be truncated (PRV-08). |
| ADR-09 | The engine works on validated UTF-8. A codec layer inside the core crate detects encodings and transcodes BOM-marked UTF-16 losslessly. Ambiguous encodings fail closed. Lossy UTF-8 repair is an explicit opt-in. | Windows PowerShell output is supported. No silent bypass (PRV-15). |
| ADR-10 | Display safety is a presentation concern. The engine never alters non-target bytes; terminal and browser renderers make control and hidden characters visible. | Byte-exact redirected output, together with protected human review (PRV-09, PRV-14). |
| ADR-11 | The CLI process is hardened. Network and process-spawning APIs are statically banned, Linux runs under a seccomp deny filter, core dumps are disabled, and panics end with a fixed message. | Defense in depth against a compromised dependency (PRV-12). |
| ADR-12 | Hosting is static and provider-neutral, with per-path response headers. There is no service worker and no cookies. | Scales on any CDN with no backend. Hosts without custom headers, such as GitHub Pages, are excluded. |
| ADR-13 | Releases are built on ephemeral GitHub-hosted runners through a reusable workflow. Each artifact gets Sigstore-signed SLSA provenance and an SBOM. PyPI uploads use Trusted Publishing with PEP 740 attestations. An independent job rebuilds every artifact to confirm reproducibility. | SLSA v1.2 Build Level 3 and verifiable releases (PRV-10). |
| ADR-14 | Dependencies are minimal and audited, with cargo-vet and cargo-deny. npm dependencies are installed from the lockfile with scripts disabled. Non-security updates wait for a cooldown period. | Smaller supply-chain attack surface (PRV-17). |
| ADR-15 | Three separately versioned contracts: CLI behavior, report schema, and rule set. | Users can pin and upgrade predictably (PRV-27). |

### 2.1 Alternatives considered for ADR-01

| Option | Parity | Worst-case performance | Distribution | Verdict |
| --- | --- | --- | --- | --- |
| Python reference plus TypeScript mirror (TRD v1.0) | Two implementations held together by tests; drift risk rated High | Python's `re` and JavaScript's `RegExp` both backtrack; hand-written Python scanners run at roughly 10 to 30 MiB/s | Pure-Python wheel, simple | Rejected: leaves PRV-01, PRV-03, and PRV-07 open |
| TypeScript core, Node.js CLI | Single implementation | V8 regex backtracks; JIT throughput is acceptable | Needs a Node.js runtime, outside the PRD's Python install channel | Rejected |
| Python core run in the browser with Pyodide | Single implementation | Slow start-up and a multi-megabyte runtime download | Very large page weight; WebAssembly needed anyway | Rejected |
| Go core compiled to WebAssembly | Single implementation | Good | WebAssembly binaries are large and carry a garbage-collected runtime; Python-wheel tooling is immature | Rejected |
| **Rust core: native plus WebAssembly** | **Single implementation; native and WebAssembly builds cross-checked** | **Linear by construction; several hundred MiB/s achievable** | **Mature wheel tooling (maturin), small WebAssembly, static binaries** | **Selected** |

The selected option costs a cross-compilation matrix and a Rust toolchain for contributors. §14.2 covers the matrix, and the `CONTRIBUTING` guide covers the toolchain. A source distribution needs a Rust toolchain to build; prebuilt wheels cover every platform in the support matrix.

## 3. System context, components, and trust boundaries

### 3.1 Components

```mermaid
flowchart LR
  subgraph BUILD["Build time, CI"]
    MAN["rules/rules.v1.json + JSON Schema"] --> GEN["build.rs: validate, generate tables, embed SHA-256"]
  end
  GEN --> CORE["spymonk-redact-core: Rust, no_std, forbid unsafe"]
  CORE --> CLI["spymonk-redact CLI: native binary"]
  CORE --> WASM["spymonk-redact-wasm: WebAssembly module"]
  CLI --> WHL["PyPI wheels with Python launcher"]
  CLI --> ARC["Standalone archives"]
  CLI --> OCI["OCI image"]
  WASM --> WRK["Module Web Worker"]
  WRK --> APP["Static web app: paste and file modes"]
  GEN --> DOCS["Generated rule docs and --list-rules"]
```

| Component | Owns | Never does |
| --- | --- | --- |
| `spymonk-redact-core` | Codec, line framing, detectors, overlap resolution, counting, hidden-character census, result model | Any I/O, logging, clocks, randomness, environment access, or panics on any input (§19.4) |
| CLI adapter (`crates/cli`) | Arguments, file and stream I/O, atomic output, terminal rendering, reports, signals, process hardening | Interpret input content; write anywhere other than stdout, stderr, the requested output, and the report file |
| WebAssembly bindings (`crates/wasm`) | Byte and string marshalling, UTF-16 offset conversion, buffer zeroing | Call JavaScript APIs other than the generated glue |
| Worker (`web/src/worker.ts`) | Message validation, job lifecycle, file streaming, output sinks | Touch the DOM, use the network, or use storage |
| Controller and UI (`web/src/`) | Editing state, revisions, rendering as text nodes, clipboard, saving | Interpret input as markup; persist anything |
| Python launcher (`python/spymonk_redact/`) | Locate the bundled binary and execute it with the same arguments | Process input |

### 3.2 Data flow and trust boundaries

```mermaid
flowchart TB
  subgraph DEV["Trust boundary 1: the user's device"]
    IN["Input: stdin, file, paste, or local file"] --> ADP["Adapter: CLI or worker"]
    ADP --> ENG["Engine: pure function over buffers"]
    ENG --> ADP
    ADP --> OUT["Sanitized output: stdout, atomic file, panel, saved file"]
    ADP --> REP["Report: counts and status, no content"]
  end
  subgraph SUP["Trust boundary 2: build and release"]
    SRC["Protected source repository"] --> CI["Ephemeral CI runners and reusable release workflow"]
    CI --> ART["Signed artifacts, provenance, SBOMs"]
  end
  subgraph DIST["Trust boundary 3: distribution"]
    REG["PyPI, GitHub Releases, container registry"]
    HOST["Static website host and CDN"]
  end
  ART --> REG
  ART --> HOST
  REG -. "install, verified by user" .-> DEV
  HOST -. "page load, assets only" .-> DEV
```

Content never crosses boundary 1. Only code crosses it, inbound, at install time or page load. §11 analyzes the threats at each boundary.

## 4. Repository, toolchain, and build structure

```text
spymonk-redact/
  README.md  LICENSE  SECURITY.md  CONTRIBUTING.md  CODE_OF_CONDUCT.md  CHANGELOG.md
  CODEOWNERS  rust-toolchain.toml  Cargo.toml  Cargo.lock  deny.toml  clippy.toml
  pyproject.toml                maturin, bindings = "bin"; at the root so the sdist carries rules/
  supply-chain/                 cargo-vet audits and imports
  rules/
    rules.v1.json               canonical rule manifest
    rules.schema.json           JSON Schema (2020-12) for the manifest
  schemas/
    report.v1.schema.json       CLI JSON report schema
    fixture.schema.json         golden-fixture schema
  fixtures/
    positive/  non-target/  overlap/  encoding/  adapters/  regression/
    benign/                     realistic synthetic logs without secrets
  crates/
    core/                       spymonk-redact-core (lib, no_std + alloc)
      build.rs                  manifest validation and code generation
      src/ codec.rs framing.rs engine.rs detectors/ resolve.rs census.rs model.rs
    cli/                        spymonk-redact (bin)
      src/ main.rs args.rs run.rs io.rs atomic.rs render.rs report.rs json.rs catalog.rs
           error.rs osrand.rs signals.rs harden/{mod,unix,linux,windows}.rs
      build.rs                  rule catalog for --list-rules; build identity
    wasm/                       spymonk-redact-wasm (cdylib)
  fuzz/                         cargo-fuzz targets
  python/
    README.md                   PyPI project description
    build-requirements.txt      hash-pinned maturin
    spymonk_redact/__init__.py  __main__.py   launcher only
  web/
    package.json  package-lock.json  tsconfig.json  vite.config.ts  index.html
    src/ main.ts controller.ts paste.ts file-mode.ts file-view.ts worker.ts worker-core.ts
         protocol.ts render.ts report.ts hidden.ts samples.ts strings.ts styles.css
         generated/rules.json   written by gen-docs from the manifest
    scripts/ build-wasm.mjs render-rules.ts verify-dist.mjs serve.mjs
    public/spymonk-mark.svg     product mark and favicon
    public/.well-known/security.txt
    hosting/headers.json        provider-neutral header policy, rendered per host
    tests/  e2e/
  tools/                        package-archive.py, check-imports.sh, check-no-network.sh,
                                fixture-inputs.py (bench: crates/core/examples/throughput.rs)
  packaging/Containerfile       FROM scratch image around the static musl binary
  .github/workflows/            ci.yml  release.yml  build-reusable.yml  scorecard.yml  fuzz.yml
  docs/                         PRD, reviews, TRD, generated rule reference, guides
```

### Toolchain pins

- Rust: an exact stable release in `rust-toolchain.toml`, edition 2024, with the `wasm32-unknown-unknown` target and pinned versions of `wasm-bindgen-cli` and `wasm-opt`.
- Node.js: an exact LTS release, recorded in `package.json` (`engines` and `packageManager`) and `web/.nvmrc` (22.23.3 at M3; moving to the Active LTS line is a tracked upgrade). `web/.npmrc` sets `ignore-scripts=true` and `save-exact=true`, and `legacy-peer-deps=true` because npm 10's peer resolver fails on Vite's optional devtools peers; every package the build uses is a declared, exactly pinned dependency.
- The WebAssembly memory cap (`--max-memory`, §11.2) is a link argument from `crates/wasm/build.rs`, because a caller-supplied `RUSTFLAGS` would replace configuration-file flags; `web/scripts/build-wasm.mjs` fails the build if the optimized module's maximum memory is not 8,192 pages.
- Python launcher: `requires-python = ">=3.11"`, reviewed each October against the CPython support schedule.
- Contributors build with `--locked`. CI fails on any lockfile drift.

### Build commands, normative

- `cargo build --locked --release -p spymonk-redact`
- `cargo build --locked --release -p spymonk-redact-wasm --target wasm32-unknown-unknown`, then `wasm-bindgen --target web` and `wasm-opt -Oz`
- `npm ci --ignore-scripts`, then `npm run build`
- `maturin build --locked --release` for the wheels

**Release profile:** `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `overflow-checks = true`, `strip = "symbols"`, `debug = false`. Paths are remapped with `--remap-path-prefix`, and `SOURCE_DATE_EPOCH` is set to the commit time.

## 5. Engine design

### 5.1 Public interface of the core crate

The interface is internal to the project in v1. It is not a published library API. The sketch below is normative for behavior; names may change during implementation.

```rust
pub struct Options { pub email: bool, pub private_ip: bool }          // defaults: true, false
pub enum InputEncoding { Auto, Utf8, Utf16Le, Utf16Be }               // default: Auto
pub enum InvalidUtf8 { Error, Replace }                               // default: Error
pub struct Limits {
    pub max_line_bytes: u32,          // default 1_048_576; valid 1_024..=67_108_864
    pub max_total_bytes: Option<u64>, // None for CLI; Some(1_048_576) for paste mode
}

pub struct Sanitizer { /* compiled rules, options, codec, framer, block state, counters */ }
impl Sanitizer {
    pub fn new(options: Options, limits: Limits, encoding: InputEncoding,
               invalid: InvalidUtf8, ranges: bool) -> Result<Self, CoreError>;
    /// Feeds arbitrary bytes and appends complete sanitized output to `out`.
    /// The caller drains `out` between calls, so memory stays bounded.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CoreError>;
    /// Flushes the final partial line and returns the summary.
    pub fn finish(self, out: &mut Vec<u8>) -> Result<Summary, CoreError>;
    /// Placeholder ranges for paste-mode highlighting (UTF-8 byte offsets into
    /// the output). The WebAssembly layer converts them to UTF-16 offsets.
    pub fn take_ranges(&mut self) -> Vec<Finding>;
}

pub fn sanitize_bytes(input: &[u8], options: Options, limits: Limits, ranges: bool)
    -> Result<(Vec<u8>, Summary, Vec<Finding>), CoreError>;  // wrapper over Sanitizer

pub struct Summary {
    pub replacements: u64,
    pub by_rule: [u64; RULE_COUNT],   // every rule ID present, zeros included
    pub lines: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub encoding: DetectedEncoding,   // Utf8 { bom: bool } | Utf16Le { bom: bool } | Utf16Be { bom: bool }
    pub invalid_utf8_replaced: u64,   // non-zero only with InvalidUtf8::Replace
    pub hidden: HiddenCensus,         // bidi, invisible, control, lone_cr
    pub warnings: WarningSet,         // UNTERMINATED_PRIVATE_KEY_BLOCK, UNSTABLE_LINE_REDACTED
    pub rules_version: &'static str,
    pub rules_sha256: &'static str,
}
pub struct Finding { pub start: u64, pub end: u64, pub rule: RuleId }
pub struct CoreError { pub code: ErrorCode, pub line: Option<u64> }
```

#### Determinism requirements

- No hash-map iteration order affects output; use arrays and ordered maps.
- No floating point, locale, time, randomness, or environment.
- ASCII-only case folding for rule matching.
- The engine contains no `unsafe` code. Its dependencies are limited to `memchr` and `aho-corasick`, each used with `default-features = false` and audited under cargo-vet.
- Lints: `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::indexing_slicing`, and `clippy::arithmetic_side_effects` are set to deny in the core crate.

### 5.2 Processing pipeline

```mermaid
flowchart LR
  B["Input bytes, any chunking"] --> D["Codec: BOM detection, UTF-16 transcoding, incremental UTF-8 validation"]
  D --> F["Framer: LF, CRLF, lone CR; carry buffer bounded by max_line_bytes"]
  F --> E["Line engine: block state, triggers, detectors, overlap resolution"]
  E --> C["Census: hidden characters"]
  C --> R["Re-encoder: original encoding and BOM"]
  R --> O["Output buffer, drained by adapter"]
```

#### Codec

- **Auto detection** inspects the first bytes:
  - `EF BB BF`: UTF-8 with a BOM.
  - `FF FE`: UTF-16LE, unless it is `FF FE 00 00`, which is UTF-32LE and rejected with `UNSUPPORTED_ENCODING`.
  - `FE FF`: UTF-16BE.
  - `00 00 FE FF`: UTF-32BE, rejected with `UNSUPPORTED_ENCODING`.
- **No BOM:** the input is UTF-8. A NUL as the first or second byte of the input, the signature of UTF-16 text that starts with an ASCII character, fails with `UTF16_WITHOUT_BOM`. Its message suggests `--input-encoding utf-16le` or `utf-16be`. Any other NUL anywhere is `NUL_BYTE`. The decision needs no look-ahead, so the error code is the same for every chunking of the input (P-5); v2.0's 4,096-byte, 30% heuristic would have had to buffer 4 KiB before emitting any output.
- **Explicit UTF-16** (`Utf16Le` or `Utf16Be`) transcodes without expecting a BOM. Unpaired surrogates, or an odd trailing byte at the end, cause `INVALID_UTF16`.
- **UTF-8 validation** is incremental. A code point split across chunk boundaries is completed by the next push. With `InvalidUtf8::Error`, the first invalid sequence fails with `INVALID_UTF8` and the line number. With `Replace`, each maximal invalid subpart becomes U+FFFD, following Unicode's "substitution of maximal subparts" practice, and is counted.
- **BOM handling.** A BOM is never treated as content. It is re-emitted in the output if, and only if, the input had one. TRD v1.0 removed the BOM; v2.0 preserves it, because byte-exact preservation overrides normalization.
- **Encoding of output.** Output uses the input's encoding. UTF-16 output is re-encoded from the sanitized UTF-8; every unchanged character round-trips exactly, because the transcoding is lossless for valid input.

#### Framer

- **Separators:** LF, CRLF, and lone CR, matching TRD v1.0 semantics. A CR at the end of a chunk is held until the next byte or the end of input. Separators are emitted unchanged.
- **Line count (`lines`):** 0 for empty input. Otherwise, the number of separators, plus one if the last character is not a separator.
- **Line limit.** A line, excluding its separator, longer than `max_line_bytes` of decoded UTF-8 fails with `LINE_TOO_LONG` and the line number. That line produces no output. Lines already emitted remain sanitized and complete.

**Line engine.** See §6 and §7. The engine processes one complete line at a time and carries only the private-key block state (§6.9) between lines.

**Census.** Counts hidden characters in the sanitized output (§9.5). The census never changes bytes.

### 5.3 Memory model

Processing is incremental across lines. Within one line, the M1 engine materializes the decoded input, a candidate list, and the sanitized output before emitting the original separator. This keeps memory bounded by the configured maximum line size, independent of total input size; it also makes every candidate available for the overlap-union rule in §7.1.

| Component | Bound |
| --- | --- |
| Decoded current line and framer carry | ≤ `max_line_bytes` |
| Sanitized current line | O(`max_line_bytes`), including placeholders and the original separator |
| Candidate list and detector scratch space | O(`max_line_bytes`) candidates for a fixed rule catalog; released before the next line |
| Private-key block state | Label of ≤ 64 bytes plus flags |
| Codec state | ≤ 4 bytes of pending code unit, plus the transcoding buffer of one chunk |

**Memory bound:** the core is O(`L`) in the configured maximum line length `L`, independent of total input size. The exact resident-memory release budget is measured on the reference machine after the CLI and WebAssembly adapters introduce their output-buffer policies; it must account for the decoded line, sanitized line, candidate list, and adapter buffers. The WebAssembly module declares a maximum linear memory of 512 MiB, so even a defect cannot grow the worker without bound.

### 5.4 Limits by surface

| Surface | Total input | Line limit | Over-limit behavior |
| --- | --- | --- | --- |
| CLI | Unlimited (streamed) | 1 MiB default; `--max-line-bytes` from 1 KiB to 64 MiB | `LINE_TOO_LONG`, exit 1, output stops before the line; `--output` leaves no file |
| Browser paste | 1 MiB of UTF-8 bytes, counted with `TextEncoder` before dispatch | 1 MiB | Output invalidated, Copy disabled, limit and actual size shown, file mode suggested |
| Browser file, saved as a Blob | 1 GiB | Same as CLI; adjustable in Advanced settings | Job fails, no save offered |
| Browser file, streamed to disk (File System Access API) | Unlimited | Same as CLI | Writable stream aborted; the browser discards its temporary file |

### 5.5 Error model

Errors are fixed codes with fixed messages. Numeric details are limited to line numbers and limits. Messages never contain input content, file names, paths, argument values, or system error text.

| Code | Origin | Meaning |
| --- | --- | --- |
| `INVALID_UTF8` | Core | Invalid UTF-8 in `Error` mode |
| `INVALID_UTF16` | Core | Unpaired surrogate or odd trailing byte |
| `UTF16_WITHOUT_BOM` | Core | Probable UTF-16 without a BOM |
| `UNSUPPORTED_ENCODING` | Core | UTF-32 or another unsupported BOM |
| `NUL_BYTE` | Core | NUL in UTF-8 input |
| `LINE_TOO_LONG` | Core | Line exceeds `max_line_bytes` |
| `INPUT_TOO_LARGE` | Core | Exceeds `max_total_bytes` (paste mode) |
| `INVALID_OPTIONS` | Core | Out-of-range limit or contradictory options |
| `INTERNAL_ERROR` | Core or adapter | Invariant violation; processing aborted, no further output |
| `INPUT_READ_FAILED` | Adapter | I/O error, unreadable or non-regular input |
| `OUTPUT_WRITE_FAILED` | Adapter | Write, sync, or rename failure; disk full |
| `OUTPUT_IS_INPUT` | CLI | The output file is the input file |
| `OUTPUT_NOT_REGULAR` | CLI | The output path exists and is not a regular file, or is a symbolic link |
| `USAGE` | CLI | Invalid arguments (exit 2) |
| `INTERRUPTED` | CLI | SIGINT, SIGTERM, or Ctrl+C |
| `WORKER_UNAVAILABLE` | Browser | Worker or WebAssembly failed to initialize |
| `PROCESSING_TIMEOUT` | Browser | Watchdog expired |
| `CANCELLED` | Browser | User cancelled a file job |

The core never returns input as a fallback. After any error, a `Sanitizer` is poisoned and refuses further `push` calls.

## 6. Detection rules

All matching is deterministic and independent of locale. Rule names and aliases use ASCII case folding. Every rule except SR-008 is line-bounded; SR-008 carries a small state across lines (§6.9). There is no entropy detector, provider lookup, network validation, decoding of nested documents, or user-supplied pattern.

### 6.1 Rule catalog

| ID | Enabled | Target | Placeholder |
| --- | --- | --- | --- |
| SR-001 | Always | Values assigned to keys whose final segment names a secret | `[REDACTED]` |
| SR-002 | Always | Credentials in `Authorization` and `Proxy-Authorization` | `[REDACTED]` |
| SR-003 | Always | Password in URL user information, any scheme | `[REDACTED]` |
| SR-004 | Always | Username segment of a home-directory path | `[USER]` |
| SR-005 | Default on | Email addresses | `[EMAIL REDACTED]` |
| SR-006 | Default off | RFC 1918 IPv4 and IPv6 unique-local (`fc00::/7`) addresses | `[PRIVATE IP REDACTED]` |
| SR-007 | Always | Known credential formats (§6.8) | `[REDACTED]` |
| SR-008 | Always | Private-key blocks | `[PRIVATE KEY REDACTED]` |
| SR-009 | Always | Cookie values in `Cookie` and `Set-Cookie` | `[REDACTED]` |

**Reserved placeholders** are exactly the five strings above: `[REDACTED]`, `[USER]`, `[EMAIL REDACTED]`, `[PRIVATE IP REDACTED]`, and `[PRIVATE KEY REDACTED]`.

**Deferred, not shown as controls** (PRV-24): hostnames, machine names, phone numbers, payment-card numbers, IPv4 or IPv6 addresses outside the private ranges, and custom rules.

#### Common boundary definitions

- *Key characters:* ASCII letters, digits, `_`, `-`, `.`
- *Token boundary* for a rule with character class C: the preceding and following characters are absent or not in C.
- *End of field:* end of line, or the matching closing quote when the field began with a quote.

### 6.2 SR-001: named secret values

#### Key recognition

- A key candidate is a maximal run of key characters, 1 to 128 bytes long, that starts at a token boundary. A leading `-` or `--` marks a command-line flag.
- The key is split into segments at `_`, `-`, and `.`, and at camel-case transitions: lower-to-upper, digit-to-upper, and the last capital of an upper-case run that is followed by a lower-case letter. Empty segments are dropped. For example, `DB_PASSWORD` gives (db, password), `clientSecret` gives (client, secret), `APIKey` gives (api, key), and `--password` gives (password).
- **Single-segment aliases**, matched against the final segment: `password`, `passwd`, `pwd`, `passphrase`, `secret`, `token`, `apikey`, `accountkey`, `sharedaccesskey`, `sig`, `credential`, `credentials`.
- **Two-segment aliases**, matched against the final two segments: `api key`, `access token`, `refresh token`, `id token`, `auth token`, `session token`, `bearer token`, `client secret`, `private key`, `secret key`, `access key`, `signing key`, `encryption key`, `master key`.
- Keys whose final segment is not an alias do not match. So `password_length`, `token_type`, `secret_name`, `max_tokens`, and `passwordHint` stay unchanged.

#### Key forms

- The key may be enclosed in matching `"` or `'`.
- It is followed by optional spaces or tabs, a separator, and optional spaces or tabs. The separators are `:`, `=`, `=>`, and `:=`.
- A flag key, starting with `-` or `--`, may instead be followed by exactly one run of spaces and then a value, as in `--password hunter2`.

#### Values

- **Quoted** (`"` or `'`): the value runs to the matching unescaped closing quote on the same line. Backslash escapes are honored when finding the boundary but are not decoded. The inside is redacted and both quotes are kept. An unterminated quoted value is redacted to the end of the line, keeping the opening quote.
- **Unquoted:** the value ends at whitespace, `,`, `;`, `&`, a quote, `(`, `)`, `[`, `]`, `{`, `}`, `<`, or `>`. Unlike v1.0, `#` is no longer a delimiter, because it occurs inside real passwords.
- **Skipped values:** an empty value, and an unquoted value that is exactly `null`, `nil`, `none`, `None`, `true`, `false`, `True`, `False`, or `undefined`. A quoted value is always redacted.
- **Placeholders:** a value that is exactly a reserved placeholder is skipped and not counted, recognized before delimiters apply. This keeps placeholders that contain spaces intact and gives idempotence.
- **Not traversed:** multi-line strings, arrays, and objects are not treated as assigned values. Other rules still apply inside them.

#### Examples

- `password=x` becomes `password=[REDACTED]`.
- `"apiKey": "x"` becomes `"apiKey": "[REDACTED]"`.
- `export GITHUB_TOKEN=x` becomes `export GITHUB_TOKEN=[REDACTED]`.
- `Server=db;Password=x;` becomes `Server=db;Password=[REDACTED];`.
- `--client-secret x` becomes `--client-secret [REDACTED]`.

### 6.3 SR-002: authorization credentials

- **Field names:** `Authorization` and `Proxy-Authorization`, case-insensitive, using SR-001's key quoting and separators. HTTP header lines, JSON, and map renderings all match.
- **Scheme with one credential token:** the value is a recognized scheme name followed by whitespace and a credential token, and the credential contains no `=` before a further character other than `=` padding. The scheme and whitespace are kept. The credential token is redacted up to whitespace, a control character, a quote, `,`, `;`, `)`, `]`, `}`, or `>`.
- **Recognized schemes** are a list in the manifest (`schemes`, case-insensitive), covering Basic, Bearer, Token, Bot, ApiKey, Digest, AWS4-HMAC-SHA256, Negotiate, NTLM, and similar. When the first word is not a listed scheme, the whole field is redacted. `Authorization: abc123 next=1` cannot otherwise be told apart from a scheme and a credential, and treating an unknown word as a scheme would leak the credential that follows it.
- **Parameterized schemes:** when the credential is a parameter list (`k=v` pairs), as in Digest or `AWS4-HMAC-SHA256`, everything after the scheme up to the end of the field is redacted.
- **No scheme:** a single bare token is redacted entirely.
- An existing placeholder in the credential position is not counted.
- Basic credentials are never decoded, and JWT contents are never parsed.

### 6.4 SR-003: URL credentials

- **Scheme:** `[A-Za-z][A-Za-z0-9+.-]{0,31}` followed by `://`, at a token boundary. Every scheme is covered, not a fixed list. For example, `jdbc:postgresql://` matches on `postgresql`.
- **URL extent:** a candidate ends at whitespace, a control character, a quote, a backtick, `<`, or `>`. Its authority ends at `/`, `?`, or `#`. `;` does not end a URL, because RFC 3986 allows it in user information (`https://user:pa;ss@host`).
- **Authority start:** the authority must start with a letter, digit, `[`, or a `:` that is followed by an `@` before the authority ends (`redis://:password@host`). Other `scheme://` text is not a URL, so it cannot shield a path or email from SR-004 and SR-005.
- **Split:** the last raw `@` in the authority separates the user information from the host. The first `:` in the user information separates the username from the password. A non-empty password is replaced, up to but not including the `@`.
- **Kept:** the scheme, username, host, port, path, query, and fragment, unless another rule targets them. For instance, SR-001 handles `?access_token=` and SR-007 handles a token used as the username.
- URLs are never re-serialized with a general URL parser. Percent-encoded passwords are redacted without decoding. IPv6 host brackets and ports are never treated as credentials.
- **Email disambiguation,** as in v1.0: inside a recognized URL authority, SR-005 may match only within the username, never across the password-to-host `@`.

### 6.5 SR-004: usernames in home-directory paths

#### POSIX forms

- `/home/<user>` and `/Users/<user>`, with case-sensitive prefixes, anywhere in a line. This also catches `/var/home/`, `/mnt/c/Users/`, and similar.
- They do not match inside a URL whose scheme is not `file`, so `https://site/home/about/` is unchanged.

#### Windows forms

- A drive letter, `:`, a separator, `Users` (ASCII case-insensitive), a separator, then the user.
- The separator is `\`, `\\` (JSON-escaped), or `/`, used consistently within one match.

#### Username grammar

- Unquoted paths: 1 to 64 characters from ASCII letters, digits, `_`, `.`, `-`, including at least one letter.
- A whole path enclosed in matching quotes on one line may also contain spaces and other Unicode, but no separators, quotes, or controls.
- The username must be followed by a separator or a path terminator: end of line, whitespace, a quote, `:`, `;`, `,`, `)`, `]`, or `}`. This catches `HOME=/home/alex` and `USERPROFILE=C:\Users\alex`.

**Not covered:** UNC paths, `~user`, `C:\Documents and Settings\`, and arbitrary occurrences of a person's name. No file-system access occurs.

### 6.6 SR-005: email addresses

The v1.0 grammar is retained.

- **Local part:** ASCII letters, digits, `.`, `_`, `%`, `+`, `-`. No leading, trailing, or repeated dots.
- **Domain:** dotted labels of letters, digits, and internal hyphens. The final label is 2 to 63 ASCII letters.
- **Boundaries:** token boundaries apply, and surrounding punctuation is kept.
- **Excluded:** quoted local parts, internationalized addresses, address literals, and single-label domains. A partial substring of an unsupported address is never redacted.
- Turning SR-005 off does not stop SR-001 from redacting an email used as a secret value.

### 6.7 SR-006: private IP addresses

#### IPv4

- Exactly four decimal octets, each 0 to 255, with no leading zeros except a lone `0`.
- Only `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` (RFC 1918) are redacted.
- Token boundaries exclude digits, `.`, letters, and `_`, so `110.0.0.1`, `10.0.0.256`, and labels inside dotted hostnames do not match.
- A port or CIDR suffix is kept.

#### IPv6 unique-local

- The RFC 4291 text forms are accepted: full form, `::` compression, and an embedded IPv4 tail. The first hextet must be `fc00` to `fdff`.
- Boundaries exclude hexadecimal digits, `:`, and `.`. A zone identifier (`%...`) and URL brackets are kept.

**Excluded:** public, loopback, link-local, carrier-grade NAT (shared address space), integer, and hexadecimal encodings. The ranges are explicit in the manifest rather than taken from a library definition.

### 6.8 SR-007: known credential formats

Each format is a manifest entry with these fields: `id`, `provider`, one or more literal case-sensitive `prefixes`, one or more body `segments`, and a `source` URL pointing to the vendor's published format. Segment character sets are `ALNUM`, `ALNUM_UPPER`, `ALNUM_US`, `ALNUM_DASH`, `B64URL`, or `B64urlDot`; each segment has a minimum length and may be exact. Matching rules:

- The prefix must start at a token boundary for the union of the prefix and body character sets.
- **Exact-length formats:** the body must be exactly `exactLen` long, followed by a boundary. A longer run does not match.
- **Minimum-length formats:** the body is the maximal run of the applicable segment character set and must meet its minimum length. A longer eligible run is redacted as a whole (up to 1,024 bytes), because a strong prefix makes over-redaction preferable to a leak.

The initial catalog is below. Lengths MUST be confirmed against each cited vendor document when the entry is added (§8.3). Every fixture uses synthetic values.

| Format ID | Provider and kind | Grammar (prefix, then body) |
| --- | --- | --- |
| `aws-access-key-id` | AWS access key ID | `AKIA` or `ASIA`, then exactly 16 `ALNUM_UPPER` |
| `github-token` | GitHub OAuth, user, server, and refresh tokens and classic PATs | `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_`, then at least 36 `ALNUM` |
| `github-fine-grained-pat` | GitHub fine-grained PAT | `github_pat_`, then at least 82 `ALNUM_US` |
| `gitlab-token` | GitLab personal, deploy, and runner tokens | `glpat-`, `gldt-`, or `glrt-`, then at least 20 `B64urlDot` |
| `slack-token` | Slack bot, user, and app tokens | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, or `xapp-`, then at least 10 `ALNUM_DASH` |
| `stripe-key` | Stripe secret and restricted keys | `sk_live_`, `sk_test_`, `rk_live_`, or `rk_test_`, then at least 16 `ALNUM` |
| `stripe-webhook-secret` | Stripe webhook signing secret | `whsec_`, then at least 24 `ALNUM` |
| `google-api-key` | Google API key | `AIza`, then exactly 35 `B64URL` |
| `openai-key` | OpenAI project, service-account, and admin keys | `sk-proj-`, `sk-svcacct-`, or `sk-admin-`, then at least 20 `B64URL` |
| `anthropic-key` | Anthropic API and admin keys | `sk-ant-`, then at least 20 `B64URL` |
| `huggingface-token` | Hugging Face access token | `hf_`, then at least 30 `ALNUM` |
| `npm-token` | npm access token | `npm_`, then exactly 36 `ALNUM` |
| `pypi-token` | PyPI API token | `pypi-AgEIcHlwaS5vcmc`, then at least 50 `B64URL` |
| `docker-pat` | Docker Hub personal access token | `dckr_pat_`, then at least 20 `B64URL` |
| `sendgrid-key` | SendGrid API key | `SG.`, then 22 `B64URL`, `.`, then 43 `B64URL` |
| `jwt` | JSON Web Token (JWS compact form) | `eyJ` plus at least 7 `B64URL`, `.`, at least 7 `B64URL`, `.`, then zero or more `B64URL` |

The JWT signature segment may be empty, which covers `alg: none` tokens. The boundary class excludes `B64URL` and `.`, so a JWE compact token's first three segments match and the overlap rules (§7) extend redaction across the joined remainder.

New formats are added as data, with no code change, provided they fit these detector types.

### 6.9 SR-008: private-key blocks

#### Armor grammar

- BEGIN: `-----BEGIN <label>-----`. END: `-----END <label>-----`, with the same label.
- The label matches `[A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?`. This covers PKCS#8, RSA, EC, DSA, OPENSSH, ENCRYPTED, and PGP private keys.
- Armor may appear anywhere in a line, so log prefixes and JSON quoting are allowed.

**Single-line form.** If an END armor with the same label follows the BEGIN armor on the same line, as in the escaped `\n` form inside JSON service-account files, the content strictly between the two armors becomes `[PRIVATE KEY REDACTED]`. That is one replacement.

**Multi-line form.** If there is no matching END on the BEGIN line:

1. Any remaining content after the BEGIN armor on that line is redacted to the end of the line.
2. The engine enters block state.
3. In block state, a line containing the matching END armor ends the block. Content before the armor is redacted; the armor and anything after it are processed normally.
4. Every other line is a body line. The first body line's content becomes `[PRIVATE KEY REDACTED]`, and later body lines become empty. Separators are kept, so the line count and the line numbers of everything after the block are unchanged.
5. The block counts as one replacement.

**Unterminated block.** If the input ends in block state, every line after the BEGIN armor has already been redacted, so the result fails closed. The summary carries the warning `UNTERMINATED_PRIVATE_KEY_BLOCK` and the line number where the block began. No cap is applied, because a cap would leak the remainder of an oversized key.

**Idempotence.** A block whose body consists only of the placeholder and empty lines is not counted again.

**Ownership.** Each block owns its byte range: on a single line, from the BEGIN armor to the end of the END armor; on a BEGIN line, from the armor to the end of the line; on an END line, from the start of the line to the end of the armor. Other rules run only on the text outside owned ranges, so a block's armor is never broken by another rule's replacement. Text after an END armor is processed normally. The one exception is FX-29: an SR-001 value that strictly encloses a complete single-line block, as in a JSON `"private_key": "-----BEGIN …-----END …-----\n"` string, is resolved together with the block as an overlap union, giving `"private_key": "[REDACTED]"`.

**Lone CR before a body line.** A body line that would become empty keeps the placeholder instead when the previous separator is a lone CR and the current one is LF or CRLF. Emptying it would join the CR and LF into one CRLF separator and change the line structure (P-2).

Other rules do not run on body lines.

**Not covered:** PuTTY `.ppk` files, and keys in binary formats or base64-encoded containers.

### 6.10 SR-009: cookie values

- **Field names:** `Cookie` and `Set-Cookie`, case-insensitive, using SR-002's key forms.
- **`Cookie`:** the value is a list of `name=value` pairs separated by `;` and optional spaces. Each non-empty value is redacted, and names, separators, and quotes are kept.
- **`Set-Cookie`:** only the first pair's value is redacted. Attributes such as `Path`, `Domain`, `Expires`, `HttpOnly`, and `SameSite` are kept.
- A quoted cookie value (RFC 6265) has its inside redacted. Text glued after the closing quote, before the next `;`, is part of a malformed value and is redacted with it.
- A recognized header (`Authorization`, `Proxy-Authorization`, `Cookie`, or `Set-Cookie`) that starts a later segment ends the cookie field and is parsed on its own, as in `Cookie: a=b; Authorization: Bearer x`.

### 6.11 Coverage limits (documented to users)

- High-entropy strings without a recognized key, header, or prefix
- Credentials split across lines, except private-key blocks
- Encoded payloads, such as base64-wrapped configuration and compressed archives
- Nested escaped logs beyond the forms listed above
- Hostnames
- Non-RFC-1918 addresses
- Personal names
- Binary files

Existing placeholders do not prove that nearby content is safe. Users must review the output. Redaction cannot undo a disclosure, and exposed credentials must be rotated.

## 7. Matching, overlap resolution, and preservation

### 7.1 Per-line algorithm

For each complete line, the engine runs these steps, carrying only the SR-008 state between lines:

1. **SR-008 state.** If the engine is in block state, apply §6.9; the other rules run only outside the ranges that blocks own (§6.9).
2. **Trigger scan.** One `aho-corasick` pass over the line locates every literal trigger: alias final segments, header names, `://`, `@`, credential prefixes, PEM armor, `/home/`, `/Users/`, and `:` followed by a separator and `Users`. A `memchr` pass locates digit runs for SR-006.
3. **Structure.** Compute URL regions (SR-003 extents), which are needed to disambiguate SR-004 and SR-005.
4. **Candidates.** Each enabled detector consumes its triggers left to right with a monotonic cursor and emits candidate ranges against the original line. Backward look-behind, such as finding a key's start, is bounded to 128 bytes. A detector never rescans bytes that its previous candidate consumed.
5. **Placeholder exemption.** Discard any candidate whose complete target is exactly a reserved placeholder, or a run of reserved placeholders with nothing between them. A larger value that merely contains a placeholder is not exempt.
6. **Merge.** K-way merge the detectors' candidate streams by (start, end). Group strictly overlapping ranges; touching ranges stay separate.
7. **Resolve and emit.** Emit each group as soon as it closes:
   - A single candidate gets its rule's placeholder.
   - Several candidates over an identical range use the highest-precedence rule's placeholder.
   - Several candidates over differing ranges are replaced by their union. The placeholder is the shared one if every candidate in the group uses the same placeholder; otherwise it is `[REDACTED]`.
   - The replacement counts once, attributed to the highest-precedence rule in the group.
   - Unchanged slices are copied byte for byte.
8. **Fixed point.** If steps 1 to 7 changed the line, run them again on the sanitized line, starting from the same SR-008 state as the first pass, and repeat until a pass changes nothing. The final pass is exactly what a second run of the engine computes for this line, so P-4 holds by construction instead of by per-rule special cases. Placeholders from earlier passes that a later replacement overlaps are absorbed into it; the others move with the text, so ranges and counts describe the final line (P-6). A line still changing after four passes is replaced entirely by `[REDACTED]`, attributed to the highest-precedence rule that still matched, and the summary carries `UNSTABLE_LINE_REDACTED` with the first such line number and the number of such lines. No supported input is known to reach the cap; it exists so that an unforeseen interaction fails closed.
9. **Separator.** Emit the line's original separator unchanged.

**Precedence, highest first:** SR-008, SR-007, SR-002, SR-009, SR-001, SR-003, SR-004, SR-005, SR-006.

#### Consequences

- `password=alex@example.com` becomes `password=[REDACTED]`, one replacement attributed to SR-001.
- `token=ghp_<36 chars>` becomes `token=[REDACTED]`, attributed to SR-007.
- Two occurrences of the same secret count as two replacements.
- The sum of the per-rule counts always equals the total.

### 7.2 Preservation invariants

Each invariant is a release gate, verified as described in §12 and §19.

- **P-1, residue equality.** Remove every output range covered by an inserted placeholder and the corresponding input ranges. The remaining byte sequences are identical.
- **P-2, line structure.** The input and output have identical separator sequences, so every terminated line keeps its number. The only line that can disappear is a final unterminated line consisting entirely of private-key body.
- **P-3, determinism.** The same input, options, and rule set give identical output bytes on every platform and build: native and WebAssembly, debug and release.
- **P-4, idempotence.** Processing the output again with the same options gives identical bytes and zero replacements.
- **P-5, chunk independence.** For any partition of the input into chunks, down to single bytes, output and summary are identical to whole-input processing.
- **P-6, count consistency.** Total replacements equal the number of inserted placeholders. Per-rule counts sum to the total. Every rule ID appears in the summary.

### 7.3 Ranges for highlighting

When ranges are requested (paste mode only), each `Finding` gives the half-open byte range of an inserted placeholder in the UTF-8 output. Unchanged existing placeholders produce no finding. The WebAssembly layer converts byte offsets to UTF-16 code-unit offsets in a single linear pass before returning them to JavaScript. Fixtures containing emoji, combining marks, and supplementary-plane characters verify the conversion.

### 7.4 Complexity guarantee

For a line of length n:

- The trigger scan is O(n) for a line of n bytes.
- Each detector is O(n) because of the monotonic cursor and bounded look-behind.
- Candidates are sorted by range and precedence before overlap resolution. For c candidates on a line, this is O(c log c); c is O(n) for the fixed rule catalog.
- Resolution is O(n + c).

The fixed point (§7.1 step 8) runs at most four passes per line, and an unchanged line needs one, so it multiplies the per-line cost by a constant. For an input of N bytes and maximum line length L, total work is O(N log L) in the current implementation. The detector count is a compile-time constant, and aliases and token prefixes are data in one compiled catalog; adding rules increases the constant factor and may increase the candidate bound. The benchmark gate in §19.9 bounds that increase.

## 8. Rule manifest, compilation, and governance

### 8.1 Manifest

`rules/rules.v1.json` is validated against `rules/rules.schema.json` (JSON Schema 2020-12). Top-level fields:

- `schemaVersion`: integer, starting at 1.
- `ruleVersion`: semantic version, starting at 1.0.0.
- `placeholders`: the reserved set.
- `precedence`: an ordered list of rule IDs.
- `rules`: an ordered array.

Each rule has a unique `id`, a `detector` type from a closed enumeration (`named-value`, `authorization`, `url-credential`, `home-path`, `email`, `private-ip`, `token-format`, `pem-block`, `cookie`), `defaultEnabled`, `optional` (whether a user toggle exists), `placeholder`, and detector-specific data: aliases, header names, ranges, or formats with `source` URLs.

The manifest is data, not code. It cannot express arbitrary patterns.

### 8.2 Build-time compilation

`crates/core/build.rs` performs these steps:

1. Parses and validates the manifest using a small validator that runs only at build time. It rejects unknown detector types, missing or duplicate IDs, a duplicate or missing precedence entry, invalid ranges, unsupported schema versions, aliases containing non-key characters, and format entries without a `source`.
2. Generates Rust tables: alias automata inputs, prefix tables, ranges, and rule metadata.
3. Computes the SHA-256 of the manifest's exact committed bytes. A CI check enforces canonical formatting of the file.
4. Embeds the rule version and the hash as constants.

A malformed manifest fails the build. It is impossible to produce a binary with a silently reduced rule set.

The rule reference in `docs/` and on the website, and the output of `--list-rules`, are generated from the compiled tables at build time. CI fails if the committed generated documentation differs from a fresh generation.

### 8.3 Governance

#### Change requirements

- Any change under `rules/` requires CODEOWNERS approval.
- Every added or changed rule or format requires:
  1. positive fixtures;
  2. negative near-miss fixtures;
  3. overlap fixtures with each interacting rule;
  4. a regression fixture for any reported defect;
  5. a `source` reference for vendor formats;
  6. a CHANGELOG entry with a fixture diff;
  7. a rule-set version change;
  8. a benchmark comparison (§19.9);
  9. a run over the benign corpus with every new change reviewed (§8.4).

#### Rule-set versioning

- **Patch:** fixes that restore documented behavior.
- **Minor:** deliberately expanded detection, such as new aliases or formats.
- **Major:** changes to existing placeholders, defaults, or precedence.

**Rule-set releases.** Rule-set and tool versions are distinct but pinned together in each artifact. A rule-set change always ships as a new tool release; rules are never updated on users' machines.

**Custom rules.** Custom rule packs are deferred (PRD §13). The detector-type design is their planned extension point: a future pack would declare data for existing detector types, carry its own version and hash, be reported in the summary, and never be able to weaken built-in rules.

### 8.4 Corpora

| Corpus | Contents | Gate |
| --- | --- | --- |
| Positive | A synthetic instance of every alias, form, scheme, format, and quoting variant | 100% redacted with the expected output |
| Non-target | Deliberate near-misses: `password_length`, `token_type`, wrong-length prefixes, `/home/about` inside URLs, public IPs | 0 changes |
| Overlap | Every pair of interacting rules | Expected union and attribution |
| Encoding | BOMs, UTF-16 in both byte orders, invalid sequences, NUL, emoji, combining marks, bidirectional characters, mixed line endings | Expected output, error, or census |
| Benign | Realistic synthetic logs from common stacks (web servers, CI, Kubernetes, Java/Python/.NET/Node stack traces, package managers) with no secrets | At most 0.5% of lines changed; every change listed and justified in review |
| Adversarial | Generated worst-case inputs: repeated triggers, long unterminated quotes, delimiter floods, maximum-length lines | Linear-time gate (§19.9) |

#### Fixture rules

- Fixtures are JSON, validated against `schemas/fixture.schema.json`, with a stable ID, input bytes encoded in base64 or text, options, expected output, the full expected summary, and an optional error code.
- Expected outputs are written and reviewed by hand and are never regenerated from the engine.
- All values are synthetic. Real leaked credentials are never accepted, even revoked ones.

#### Normative examples, carried from v1.0 and extended

| ID | Input | Options | Expected output | Count |
| --- | --- | --- | --- | --- |
| FX-01 | `password=fake-value` | Default | `password=[REDACTED]` | 1 |
| FX-02 | `{"api_key":"fake-key"}` | Default | `{"api_key":"[REDACTED]"}` | 1 |
| FX-03 | `Authorization: Bearer fake-token` | Default | `Authorization: Bearer [REDACTED]` | 1 |
| FX-04 | `postgresql://app:fake-pass@db/app` | Default | `postgresql://app:[REDACTED]@db/app` | 1 |
| FX-05 | `/home/alex/app/config.yml` | Default | `/home/[USER]/app/config.yml` | 1 |
| FX-06 | `C:\Users\alex\app.log` | Default | `C:\Users\[USER]\app.log` | 1 |
| FX-07 | `user=alex@example.com` | Default | `user=[EMAIL REDACTED]` | 1 |
| FX-08 | `user=alex@example.com` | Email off | Unchanged | 0 |
| FX-09 | `host=10.0.0.8:5432` | Default | Unchanged | 0 |
| FX-10 | `host=10.0.0.8:5432` | Private IP on | `host=[PRIVATE IP REDACTED]:5432` | 1 |
| FX-11 | `password=alex@example.com` | Default | `password=[REDACTED]` | 1 |
| FX-12 | `password=[REDACTED]` | Default | Unchanged | 0 |
| FX-13 | `password_length=16` | Default | Unchanged | 0 |
| FX-14 | `host=172.32.0.1` | Private IP on | Unchanged | 0 |
| FX-15 | `DB_PASSWORD=fake` | Default | `DB_PASSWORD=[REDACTED]` | 1 |
| FX-16 | `"clientSecret": "fake"` | Default | `"clientSecret": "[REDACTED]"` | 1 |
| FX-17 | `--password fake --verbose` | Default | `--password [REDACTED] --verbose` | 1 |
| FX-18 | `Cookie: sid=fake; theme=dark` | Default | `Cookie: sid=[REDACTED]; theme=[REDACTED]` | 2 |
| FX-19 | `Set-Cookie: sid=fake; Path=/; HttpOnly` | Default | `Set-Cookie: sid=[REDACTED]; Path=/; HttpOnly` | 1 |
| FX-20 | `remote: https://user:fake@git.example/r.git` | Default | `remote: https://user:[REDACTED]@git.example/r.git` | 1 |
| FX-21 | `key AKIA` + 16 synthetic upper-case characters | Default | `key [REDACTED]` | 1 |
| FX-22 | `"key_material": "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"` | Default | `"key_material": "-----BEGIN PRIVATE KEY-----[PRIVATE KEY REDACTED]-----END PRIVATE KEY-----\n"` | 1 |
| FX-23 | Multi-line PEM block, 3 body lines | Default | Armor kept; body is the placeholder plus 2 empty lines; same line count | 1 |
| FX-24 | `HOME=/home/alex` | Default | `HOME=/home/[USER]` | 1 |
| FX-25 | `see https://example.com/home/about/` | Default | Unchanged | 0 |
| FX-26 | `addr=[fd12:3456::1]:443` | Private IP on | `addr=[[PRIVATE IP REDACTED]]:443` | 1 |
| FX-27 | UTF-16LE with BOM containing `password=fake` | Default | UTF-16LE with BOM containing `password=[REDACTED]` | 1 |
| FX-28 | `token_type=Bearer max_tokens=10` | Default | Unchanged | 0 |
| FX-29 | `"private_key": "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"` | Default | `"private_key": "[REDACTED]"` | 1 |

In FX-22 the key is not a secret alias, so only SR-008 applies and the armor is kept. In FX-29, the SR-001 candidate (the whole quoted value) and the SR-008 candidate (the content between the armors) overlap with different ranges. §7.1 step 7 therefore replaces their union with `[REDACTED]` and attributes the single replacement to SR-008, the higher-precedence rule.

## 9. CLI design

### 9.1 Command surface

```text
spymonk-redact [OPTIONS] [FILE | -]

Input and output
  -o, --output PATH          Write sanitized output atomically to PATH (stdout stays empty)
      --input-encoding ENC   auto (default) | utf-8 | utf-16le | utf-16be
      --invalid-utf8 MODE    error (default) | replace
      --max-line-bytes N     Default 1048576; accepted range 1024 to 67108864
Rules
      --disable-email
      --enable-private-ip
      --list-rules           Print the rule catalog and exit (honors --report-format)
Reporting
      --report               Print a summary to stderr
      --report-format FMT    text (default) | json
      --report-file PATH     Write the report to PATH atomically, instead of stderr
Display
      --escape-controls MODE auto (default: when stdout is a terminal) | always | never
Information
  -h, --help
  -V, --version
```

#### Operands

- No operand, or `-`, selects standard input. One operand selects a file. More than one operand is a usage error.
- `--` ends option parsing, so a file name may begin with `-`.
- The CLI performs no recursion, wildcard expansion, configuration-file discovery, environment-variable configuration, clipboard access, in-place editing, or network activity.

#### Argument parsing

- Arguments are parsed with `lexopt`, a minimal parser with no dependencies.
- Usage errors print fixed messages naming the option, never the user-supplied value, and exit with 2.
- Non-UTF-8 arguments are rejected with a fixed message.

**Report options.** `--report-format` or `--report-file` on its own turns reporting on; `--report` is not also needed.

**Interactive standard input.** When standard input is an interactive terminal and no file is given, the CLI prints a fixed usage hint and exits with 2 instead of waiting. An empty pipe or an empty file is valid input.

**Pipelines.** For scale across many files, users run one process per file with `xargs -P` or `find -exec`. The documentation shows this pattern, which uses every core with no shared state.

### 9.2 Input handling

- A file operand is opened read-only, and its type is checked through the open handle (`fstat` or `GetFileInformationByHandle`), so the check and the open refer to the same file. On Unix the open uses `O_NONBLOCK`, so a FIFO operand is rejected instead of blocking the open. Directories, FIFOs, devices, and sockets are rejected with `INPUT_READ_FAILED`. Standard input may be a pipe, file, or terminal.
- Input is read in 64 KiB chunks and passed to `Sanitizer::push`. Output is drained after each chunk.
- The input file is never opened for writing. Its contents, permissions, and timestamps are untouched. Access time may change according to the operating system's mount options.

### 9.3 Atomic output (`--output`, `--report-file`)

Before reading any input, the CLI checks the output path:

1. **Same file.** If the path exists and has the same file identity as the input (device and inode on Unix; volume serial number and file index on Windows), the run fails with `OUTPUT_IS_INPUT` before anything is read.
2. **Not a regular file.** If the path exists and is a symbolic link, directory, or other non-regular file, the run fails with `OUTPUT_NOT_REGULAR`.
3. **Temporary file.** The CLI creates a temporary file in the target's directory, named `.<target>.<random 128-bit hex>.tmp`. It is opened create-new and without following links (`O_CREAT|O_EXCL|O_NOFOLLOW` on Unix; `CREATE_NEW` on Windows), with mode `0600` on Unix and the directory's inherited ACL on Windows. Randomness comes from the operating system's random source (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows); this is the only use of randomness, and it never affects content.
4. **Write.** Output streams into the temporary file.
5. **Commit.** On success, the CLI flushes the file, syncs it (`fsync` or `FlushFileBuffers`), renames it over the target (`rename`, or `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`), and on Unix syncs the directory.
6. **Failure.** On any error, signal, or panic, the temporary file is deleted and the target is untouched.

The new file does not inherit an existing target's permissions; it is created private by default. Concurrent runs that target the same path each produce a complete file, and the last rename wins.

### 9.4 Standard output behavior

- Output is written as raw bytes in the input's encoding. Nothing is added: no newline, color, or banner. Output is written whenever the 64 KiB buffer fills, and once more at the end, so memory stays bounded while streaming.
- If a failure occurs while streaming, emitted output stops at the last complete line. The exit code is non-zero, and the report shows `"outputComplete": false`. Pipelines that need completeness use `--output` or check the report.
- **Broken pipe.** Processing stops silently: nothing is written to standard error and no report is produced. The exit code is 141 on Unix, matching the shell convention for SIGPIPE, and 1 on Windows.
- **Interruption.** SIGINT, SIGTERM, and Ctrl+C set a flag that is checked between chunks and lines. The CLI removes its temporary files and exits with 130 (SIGINT or Ctrl+C) or 143 (SIGTERM). The handlers are the CLI's own (`sigaction` without `SA_RESTART`, so a blocking read returns and the flag is seen; `SetConsoleCtrlHandler` on Windows) and only store the signal number; `ctrlc` cannot tell SIGINT from SIGTERM.

### 9.5 Terminal rendering (display safety)

When `--escape-controls` resolves to on (the default when standard output is a terminal), the renderer, not the engine, replaces each of the following with a visible marker:

- C0 controls except TAB, LF, and CR in CRLF;
- a lone CR, rendered as `<CR>` followed by a line feed;
- DEL and C1 controls;
- bidirectional controls: U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069;
- invisible characters: U+00AD, U+034F, U+115F, U+1160, U+17B4, U+17B5, U+180E, U+200B to U+200D, U+2060 to U+2064, U+3164, U+FEFF other than a leading BOM, U+FFA0, and the tag characters U+E0000 to U+E007F.

The marker is `<U+XXXX>`. This blocks terminal escape injection (CWE-150) and visual overwrite of content.

Escaping applies only to standard output: a file written with `--output` is always byte-exact, whatever `--escape-controls` says. When standard output is redirected, `--escape-controls` resolves to off and output stays byte-exact. `--escape-controls always` forces visible markers even when redirected; the report then records `"displayEscaped": true`. On Windows consoles, output is written as UTF-16 through the console API, as the Rust standard library does for console handles, and virtual-terminal processing is never enabled by the tool.

The census counts each category in every mode. A non-zero count adds the notice line `Output contains N hidden or control characters; they may change how text appears.`

### 9.6 Reports, notice, and version

Every successful run prints this fixed notice to standard error, whether or not a report is requested:

```text
Review output before sharing; detection is limited. Rotate any credential that was already exposed.
```

**Text report** (`--report`), always on standard error unless `--report-file` is given:

```text
spymonk-redact: status=complete replacements=3 lines=4 email=on private_ip=off rules=1.0.0
spymonk-redact: SR-001=2 SR-004=1
spymonk-redact: encoding=utf-8 bom=no hidden bidi=0 invisible=0 control=0 lone_cr=0
```

Per-rule counts appear in rule-ID order, only when non-zero; zero replacements prints `none`.

**JSON report** (`--report-format json`). It validates against `schemas/report.v1.schema.json` (JSON Schema 2020-12) and is written as one line of JSON:

```json
{
  "schemaVersion": 1,
  "tool": { "name": "spymonk-redact", "version": "1.0.0", "build": "<commit>", "target": "x86_64-unknown-linux-gnu" },
  "rules": { "version": "1.0.0", "sha256": "<hex>" },
  "options": { "email": true, "privateIp": false, "maxLineBytes": 1048576, "invalidUtf8": "error", "inputEncoding": "auto" },
  "status": "complete",
  "outputComplete": true,
  "input": { "encoding": "utf-8", "bom": false, "bytes": 1234, "lines": 4 },
  "output": { "bytes": 1250, "displayEscaped": false },
  "replacements": { "total": 3, "byRule": { "SR-001": 2, "SR-002": 0, "SR-003": 0, "SR-004": 1, "SR-005": 0, "SR-006": 0, "SR-007": 0, "SR-008": 0, "SR-009": 0 } },
  "hidden": { "bidi": 0, "invisible": 0, "control": 0, "loneCr": 0 },
  "invalidUtf8Replaced": 0,
  "warnings": [],
  "sandbox": "seccomp",
  "error": null,
  "notice": "Review output before sharing; detection is limited. Rotate any credential that was already exposed."
}
```

- On failure, a report is still produced when requested, with `"status": "failed"`, `"outputComplete": false`, and `"error": { "code": "LINE_TOO_LONG", "line": 812 }`. Fields that need the final summary (`input.lines`, `replacements`, `hidden`, `invalidUtf8Replaced`) are `null`, and `input.encoding` is `null` when the failure came before any input was read.
- `sandbox` is `seccomp` when the Linux filter is active, `process-mitigations` when every Windows mitigation policy applied, and `none` otherwise.
- The text report adds `error=CODE line=N` after a failure and one line per warning.
- When the JSON report goes to standard error, standard error carries exactly one JSON document. The review notice and the hidden-character notice appear only inside it, in `notice`, `hidden`, and `warnings`, and are not printed as extra text lines, so machine parsing stays reliable. With `--report-file`, the plain-text notices still go to standard error.
- Reports never contain matched values, input content, file names, paths, hashes of content, or environment data.
- Byte counts and line counts are considered safe metadata.

**`--version`** prints the tool version, rule-set version, rule-set SHA-256, commit, build target, and build date, which comes from `SOURCE_DATE_EPOCH`.

**`--list-rules`** prints each rule's ID, family, default, optional flag, and placeholder, and, for SR-007, every format ID and its provider.

### 9.7 Exit codes

| Code | Meaning | Standard output |
| --- | --- | --- |
| 0 | Success, help, version, or list-rules | Complete sanitized output or the requested information |
| 1 | Input, encoding, limit, processing, or output failure | Empty if the failure occurred before output began; otherwise the complete lines before the failure, with the report marked incomplete |
| 2 | Usage error | Empty |
| 130 / 143 | Interrupted by SIGINT or Ctrl+C / by SIGTERM | As for 1 |
| 141 | Broken pipe (Unix) | Consumer closed the pipe |

### 9.8 Process hardening

These steps run at start-up, before any input is read:

- **Core dumps.** Unix: `setrlimit(RLIMIT_CORE, 0)`. Linux also sets `prctl(PR_SET_DUMPABLE, 0)`, which blocks same-user ptrace attachment and core dumps.
- **Windows mitigations.** Error dialogs are suppressed with `SetErrorMode`, and available process mitigation policies are applied through `SetProcessMitigationPolicy`: dynamic-code prohibition, extension-point disablement, and strict handle checks. Policies the OS cannot apply are skipped and recorded.
- **Panics.** The release profile uses `panic = "abort"`. A panic hook prints only `spymonk-redact: internal error (INTERNAL_ERROR)`, deletes temporary files, and exits with code 1 without calling `abort`, so no crash dump is produced. The panic payload, which might contain data, is never printed.
- **Linux seccomp.** After the input, output, and temporary-file handles are open, a seccomp-BPF deny filter (built with `seccompiler`, with no libseccomp dependency) returns `EPERM` for `socket`, `socketpair`, `connect`, `bind`, `listen`, `accept`, `accept4`, `sendto`, `sendmsg`, `sendmmsg`, `execve`, `execveat`, `ptrace`, `process_vm_readv`, and `process_vm_writev`. If the kernel refuses the filter, processing continues and the report records `"sandbox": "none"`.
- **No environment access.** The CLI reads no environment variables at all; terminal rendering is decided by whether standard output is a terminal. Build scripts read Cargo's build variables, which only become fixed strings in the binary.
- **Static bans.** `clippy.toml` uses `disallowed-types` and `disallowed-methods` to forbid `std::net::*`, `std::process::Command`, and `std::env::var*`. File opens are confined to `io.rs`, `atomic.rs`, and `osrand.rs` (`/dev/urandom`) by review, because Clippy bans cannot be scoped to modules. `deny.toml` bans networking and process crates, including `reqwest`, `hyper`, `h2`, `ureq`, `curl`, `isahc`, `tokio` with `net`, `mio`, `socket2`, `openssl`, `native-tls`, `rustls`, and `duct`.
- **Release check.** CI inspects each release binary's imported symbols and DLLs and fails if any socket, DNS, HTTP, or process-creation API is imported. The tools are `nm -D` or `readelf` for ELF, `dyld_info` or `otool` for Mach-O, and `dumpbin /imports` or `llvm-objdump` for PE. If a platform's standard library always links a networking DLL, the check asserts at symbol level that no networking function is referenced, and the runtime test (§19.7) confirms that none is ever called.

### 9.9 Python launcher

`python/spymonk_redact/__main__.py` finds the binary that maturin installed in the environment's scripts directory, or next to the package, and runs it with identical arguments: `os.execv` on Unix, or a subprocess on Windows that passes the exit code through. It has no dependencies and does not read or alter input. Its only purpose is to make `python -m spymonk_redact` work. The console entry point `spymonk-redact` is the binary itself.

## 10. Browser application design

### 10.1 Pages and content

The site is one static page with these sections:

- Overview
- Playground, with Paste and File tabs
- Rules, generated from the compiled manifest
- Install and verify
- Security and privacy, including a summary of the threat model, the privacy notice, a link to `security.txt`, and site verification steps
- A link to the repository

The footer shows the build identity: tool version, rule-set version and hash, and commit.

Navigation uses fragment identifiers for section names only. Input never appears in a URL. Text that the page sets at run time (statuses, errors, warnings, labels) lives in `strings.ts`, ready for localization; the static document copy lives in `index.html`, so the page reads without JavaScript. The Rules section is rendered into `index.html` at build time from `web/src/generated/rules.json`, which `gen-docs` produces from the manifest and `--check` keeps current. The product mark shown in the header is the same file the page uses as its favicon; no framework default icon ships. External links use `rel="noopener noreferrer"` and fixed URLs, and link prefetching and prerendering are disabled.

### 10.2 Paste mode

#### Controls

- A labelled `<textarea>` editor with `autocomplete="off"`, `spellcheck="false"`, `autocapitalize="off"`, `autocorrect="off"`, `translate="no"`, `data-gramm="false"`, `data-gramm_editor="false"`, and `data-enable-grammarly="false"`. The editor-assistant attributes are best-effort hints; extensions are outside the trust boundary.
- A read-only output panel.
- A sample selector with a Load button and three bundled synthetic samples: an API log, a config excerpt, and a stack trace. Loading a sample over non-empty edited input asks for confirmation first.
- Email and private-IP toggles.
- Copy output and Clear buttons.
- The status region.

**Limits.** Input is limited to 1 MiB of UTF-8, measured with `TextEncoder.encodeInto` into a reusable buffer. The page shows replacements, per-rule counts, lines, active options, the rule-set version, and hidden-character counts.

#### Status text

- With no matches: "No matches found — review before sharing".
- Otherwise, for example: "3 replacements — review before sharing".
- The page never says "safe" and shows no risk score.

**States:** `initializing`, `empty`, `pending`, `ready`, `error`, `unavailable`. Input is disabled until the worker reports that it is ready.

**Revisions and dispatch** (retained from v1.0)

- Every edit, sample load, or option change synchronously increments the revision, clears the accepted result, and disables Copy.
- Empty input moves to `empty` without a scan.
- Dispatch is debounced by 150 ms.
- At most one request is in flight, with one pending request; a newer request replaces the pending one.
- A result is accepted only if its revision, options, and rule-set hash match the current state.

**Timeout.** The watchdog allows 2 seconds per scan. On expiry, the controller terminates the worker, clears results, shows the timeout, and starts one fresh worker from the same immutable, hashed script URL. The browser normally serves that script from its HTTP cache. Re-creation sends no input, and the request, if one is made, is the same static-asset request as at start-up. If re-creation fails, for example while offline with an evicted cache, or if a second consecutive failure occurs, the state moves to `unavailable` and the page recommends a reload or the CLI.

**Highlighting.** Up to 10,000 inserted placeholders are highlighted, using DOM elements built from the UTF-16 ranges. Beyond that, the output appears as plain text with a notice that highlighting is limited. Redaction itself is complete either way.

**Hidden characters.** In the output panel, hidden and control characters (the §9.5 set) appear as visible badges such as `⟨U+202E⟩`, with a toggle that is on by default. Copy always copies the sanitized string faithfully, not the badge rendering. When hidden characters are present, the status shows a warning.

### 10.3 Copy behavior

These rules are retained from v1.0:

- Copy is enabled only for a non-empty accepted result that belongs to the current revision and options.
- At click time, the controller re-checks the result and captures the sanitized string. It calls `navigator.clipboard.writeText` within the user's action and shows "Copied sanitized output" only after the promise resolves.
- If the user edits while the copy is in progress, the previously validated snapshot may finish copying, but the new revision is never shown as copied.
- On failure, the result stays visible and the output can be selected for manual copying.
- The page never reads the clipboard, auto-copies, or clears the clipboard.
- In file mode, Copy is available only when the complete output is 1 MiB or less.

### 10.4 File mode

#### Input

- An `<input type="file">` button, plus a drop zone. The button is the keyboard and assistive-technology alternative required by WCAG 2.2 criterion 2.5.7.
- The `File` object is posted to the worker, which reads it with `File.slice()` in exact 1 MiB chunks, giving byte-accurate progress. The main thread never holds the content.

#### Output sinks

- **Stream to disk.** Where `showSaveFilePicker` is available, the user picks the destination first. The `FileSystemFileHandle` is posted to the worker, which writes through a `FileSystemWritableFileStream`. Browsers stage writes in a temporary file and commit only on `close()`, so the save is atomic. On failure or cancel, the worker calls `abort()`. There is no size limit.
- **Blob.** Elsewhere, output chunks accumulate as Blob parts, up to the 1 GiB limit. Only after successful completion does the main thread create an object URL and enable "Save sanitized file". The URL is revoked after the save, on Clear, and on `pagehide`.

**Progress and watchdog.** Progress shows bytes processed out of the total, and the user can cancel. The watchdog terminates the job if no chunk completes within 5 seconds.

**Preview.** The page renders the first 64 KiB of sanitized output, with highlighting, and the full summary.

**Suggested file name.** `<name>.redacted<ext>`, computed locally. The original name is never sent anywhere.

**Parity.** For the same bytes and options, file-mode output is byte-identical to the CLI's (§19.6).

### 10.5 Worker protocol

Messages are structured-clone objects. Both sides validate every field: exact `type` values, integer ranges, booleans, and object shapes. Unknown or malformed messages are dropped and counted, never interpreted.

```text
Page to worker
  { type: "init" }
  { type: "paste", revision: int, text: string, options: Options }
  { type: "fileStart", job: int, file: File, options: Options, maxLineBytes: int,
    sink: "blob" | "handle", handle?: FileSystemFileHandle }
  { type: "cancel", job: int }

Worker to page
  { type: "ready", rulesVersion, rulesSha256, toolVersion }
  { type: "pasteResult", revision, output: string, summary: Summary, ranges: Int32Array }
  { type: "fileProgress", job, bytesDone, bytesTotal }
  { type: "fileResult", job, summary: Summary, preview: string, blob?: Blob }
  { type: "error", revision?: int, job?: int, code: ErrorCode }
```

- Paste mode and file mode each have a worker, created eagerly from the same hashed script. A paste watchdog restart therefore never ends a running file job.
- A worker holds no state other than its current job.
- After each paste job, the WebAssembly layer zeroes its input and output buffers before freeing them, using the `zeroize` crate.
- JavaScript strings are immutable and cannot be zeroed. The documentation says so (§11.4).

### 10.6 Rendering and DOM safety

- Content derived from input enters the DOM only through `textContent`, `textarea.value`, and `document.createElement`. The code never uses `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function`, or string timers.
- The CSP directives `require-trusted-types-for 'script'` and `trusted-types spymonk-worker` make every string-to-HTML sink throw at run time. That turns any regression into a visible failure rather than a silent cross-site scripting bug. The `Worker` constructor is itself a Trusted Types sink, so `trusted-types 'none'` would also block the engine; the page therefore creates exactly one policy, `spymonk-worker`, whose `createScriptURL` accepts only the build's hashed worker URL and throws for anything else. No `createHTML` or `createScript` exists. The worker's own policy remains `trusted-types 'none'`.
- Trusted Types reached Baseline browser support in February 2026. In older browsers, the static ban, enforced by ESLint `no-restricted-properties` and `no-restricted-syntax` together with CodeQL, remains the control.

### 10.7 Accessibility (WCAG 2.2 AA)

- Explicit labels and a logical tab order.
- A polite live region that announces completed updates, not keystrokes.
- Status conveyed in text as well as color, with text contrast of at least 4.5:1 and non-text contrast of at least 3:1.
- Focus is visible and never obscured (2.4.11).
- Targets are at least 24×24 CSS pixels (2.5.8).
- A file-picker alternative to dragging (2.5.7).
- Consistent help placement (3.2.6).
- No horizontal page overflow at 320 px; long lines scroll within their panel.
- Input focus is kept during result updates.
- Reduced motion is respected.

The automated axe-core check is necessary but not sufficient. A manual test with NVDA and Firefox on Windows, and with VoiceOver and Safari on macOS, is a release gate (§19.10).

### 10.8 Delivery, offline behavior, and lifecycle

#### Asset delivery

- All assets are served from the same origin over HTTPS and use system fonts.
- The main thread is bundled into one ES module with no code splitting, protected by Subresource Integrity (`integrity="sha384-…"`), along with one stylesheet that also carries SRI. The WebAssembly bytes are embedded in the hashed worker script.
- Vite's module-preload polyfill is disabled, because it uses `fetch`.
- The worker and the WebAssembly module are created eagerly at start-up, so a loaded page works offline. A first visit while offline is not supported. There is no service worker, which avoids persistent caches and a second code-update channel.

#### Lifecycle

- On `pagehide`, the page clears the editor, output, results, object URLs, and the worker.
- On `pageshow` with `persisted` set, it re-initializes before accepting input.
- Clear discards all state and restores the default toggles.

**Storage.** The page uses no `localStorage`, `sessionStorage`, IndexedDB, Cache API, or cookies. Tests enforce this (§19.7).

**Self-hosting.** A meta CSP equivalent to the header policy, minus `frame-ancestors`, which meta tags cannot carry, is embedded in `index.html`. That way, a verified offline bundle served locally, for example with `python -m http.server --bind 127.0.0.1`, keeps the protections. Opening the file directly with `file://` is not supported.

## 11. Security architecture

### 11.1 Threat model

#### Assets

- A1: the user's input and the secrets in it
- A2: sanitized output, which the recipient relies on
- A3: the rule set
- A4: release artifacts
- A5: the website's code
- A6: maintainer accounts and signing identities

#### Actors

- the recipient of shared text
- the author of crafted input, relevant when the tool runs in automation over third-party content
- a malicious or compromised dependency
- an attacker who has compromised a maintainer account, the CI system, a package registry, or the website host
- a local attacker on the user's machine (out of scope beyond hardening)

STRIDE categories: S = spoofing, T = tampering, R = repudiation, I = information disclosure, D = denial of service, E = elevation of privilege.

| ID | Threat | STRIDE | Boundary | Mitigations | Residual risk and verification |
| --- | --- | --- | --- | --- | --- |
| T-01 | A secret outside the detection grammar reaches the recipient | I | 1 | Expanded default rules (§6), the review notice, the hidden-character census, documented coverage limits, and corpus gates (§8.4) | Inherent to pattern detection; stated to users. Verified by corpus recall of 100% |
| T-02 | A supported secret survives because of a parser or overlap defect | I | 1 | Single engine, overlap union rule, property tests P-1 to P-6, fuzzing, mutation testing | A release blocker (§21). §19.2 to §19.5 |
| T-03 | Crafted input causes super-linear time or unbounded memory | D | 1 | Linear detectors (§7.4), line limit, memory budget (§5.3), WebAssembly memory cap, watchdogs | §19.9 adversarial gate; fuzz timeouts and out-of-memory findings block release |
| T-04 | Terminal escape sequences in output manipulate the user's terminal | T, E | 1 | Terminal rendering (§9.5), on by default for terminals | PTY tests (§19.6) |
| T-05 | Bidirectional, invisible, or tag characters, or lone CRs, hide content from the reviewer | S | 1 | Census, notices, visible markers in the CLI and browser | §19.6 and §19.8 |
| T-06 | Input rendered as markup executes script in the playground | E, I | 1 | Text-node-only rendering, Trusted Types with no policy, strict CSP, lint bans | §19.8 HTML and script canaries; CodeQL |
| T-07 | Copy places raw or stale text on the clipboard | I | 1 | Revision-bound snapshot copy (§10.3) | §19.8 race tests |
| T-08 | A compromised dependency exfiltrates content | I | 2 → 1 | Engine has no `std`; static bans on network and process APIs; seccomp; `connect-src 'none'` in page and worker; cargo-vet, cargo-deny, lockfiles, cooldown; SBOM | §19.7 network-zero tests; dependency review |
| T-09 | Compromised CI or maintainer account publishes a malicious release | T | 2 | Phishing-resistant 2FA; protected branch and release environment; reusable-workflow SLSA Build L3 provenance; Trusted Publishing (no long-lived tokens); signed tags; independent reproducibility rebuild | §14.6 verification by users and CI |
| T-10 | Compromised website host or CDN serves modified JavaScript | T, I | 3 → 1 | SRI on page assets; immutable hashed names; deploys only from CI using short-lived OIDC credentials; published asset hashes and verification script; verified offline bundle; HSTS preload; DNS CAA and DNSSEC; users told that each visit trusts the host | A fully compromised host that also controls the HTML can bypass SRI and CSP. This residual risk is stated, with the CLI or offline bundle as the mitigation. `tools/verify-site` |
| T-11 | Output file mishandling: overwriting the input, symlink redirection, permissive permissions, partial files | T, I | 1 | Same-file refusal, no-follow create-new temporary file, `0600` permissions, atomic rename (§9.3) | §19.6 failure injection |
| T-12 | Content leaks through errors, logs, crash dumps, panics, or reports | I | 1 | Fixed messages, no content in reports, panic hook, core dumps disabled, no telemetry | §19.6 canary search over all diagnostic output |
| T-13 | Content leaks through browser features: storage, URL, translation, prefetch, extensions | I | 1 | No storage or URL state; `translate="no"`; editor-assistant hints; no prefetch | Extensions are out of scope (stated). §19.7 |
| T-14 | Typosquatted or look-alike packages | S | 3 | Reserve names on PyPI, crates.io, and the container registry; documentation links only to the official sources; verification instructions | Owner action (§23) |
| T-15 | A false "already redacted" impression from placeholder-like text in input | S | 1 | Only exact placeholders are exempt; containing values are redacted; the census and review notice apply | Fixtures FX-12 and the placeholder near-miss family |
| T-16 | The rule set is tampered with on disk after install | T | 1 | Rules are compiled into the signed binary; `--version` hash matches the release notes | Local-administrator compromise is out of scope |
| T-17 | Repudiation: a user cannot show which rules sanitized an artifact | R | 1 | Report carries the tool version, rule version and hash, and options | §19.6 schema tests |

**Explicitly out of scope:** a compromised operating system, malicious browser extensions, clipboard-history tools, screen capture, swap and hibernation files, and the security of wherever the user shares output.

### 11.2 Security controls by component

| Component | Controls |
| --- | --- |
| Engine | `no_std`; `#![forbid(unsafe_code)]`; deny-level clippy lints for panics, indexing, and arithmetic (§5.1); total functions; poisoned on error; fuzzed; `memchr` and `aho-corasick` audited |
| CLI | §9.2 to §9.8: argument handling without echo, handle-based file checks, atomic output, terminal rendering, hardening, static and binary bans |
| WebAssembly | Maximum memory 512 MiB; exports limited to the sanitizer API; buffers zeroed after paste jobs; instantiated only inside the worker |
| Worker | Strict message validation; no DOM; no network (`connect-src 'none'`); its own CSP; one job at a time |
| Page | Text-only rendering; Trusted Types; SRI; no third-party resources; no storage; strict headers (§11.3) |
| Build and release | §14 |
| Repository | §15 |

### 11.3 Web response headers

The provider-neutral policy lives in `web/hosting/headers.json`. It is rendered into the chosen host's configuration format, and CI checks the deployed headers after every deploy.

#### Main page (`/` and `index.html`)

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
  font-src 'none'; connect-src 'none'; worker-src 'self'; manifest-src 'none'; media-src 'none';
  object-src 'none'; frame-src 'none'; child-src 'none'; base-uri 'none'; form-action 'none';
  frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types spymonk-worker
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Permissions-Policy: accelerometer=(), autoplay=(), bluetooth=(), browsing-topics=(), camera=(),
  clipboard-read=(), clipboard-write=(self), display-capture=(), encrypted-media=(), fullscreen=(),
  geolocation=(), gyroscope=(), hid=(), idle-detection=(), local-fonts=(), magnetometer=(),
  microphone=(), midi=(), payment=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(),
  usb=(), xr-spatial-tracking=()
Cache-Control: no-cache
```

**Worker script (`/assets/worker-*.js`)**

```text
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'none';
  require-trusted-types-for 'script'; trusted-types 'none'
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
Cache-Control: public, max-age=31536000, immutable
```

`'wasm-unsafe-eval'` allows only WebAssembly compilation, not JavaScript evaluation, and appears only in the worker's policy.

**Other hashed assets:** `Cache-Control: public, max-age=31536000, immutable`, `X-Content-Type-Options: nosniff`, and `Cross-Origin-Resource-Policy: same-origin`.

**Never present:** `Set-Cookie`, CSP reporting endpoints, analytics or bot-management injection, or any third-party origin.

**Domain:** a CAA record restricted to the chosen certificate authority, DNSSEC where the registrar supports it, and HSTS preload submission after a stable period.

**`/.well-known/security.txt`** follows RFC 9116, with `Contact`, `Expires`, `Policy`, `Preferred-Languages`, and `Canonical` fields, and is signed with the project's OpenPGP key if one exists. `Canonical` is added when the website's domain is chosen (§23); until then the file carries the other four fields.

### 11.4 Data lifetime and remanence

| Location | Lifetime | Control |
| --- | --- | --- |
| CLI process memory | Until exit | Buffers are reused per chunk; content is not retained after it is written; core dumps disabled; secure erasure is not guaranteed because of the allocator and OS paging (documented) |
| Temporary output file | Until rename or deletion | `0600` (Unix); deleted on every failure path |
| Browser main-thread strings | Until garbage collection | References dropped on supersession, Clear, and `pagehide`; JavaScript strings cannot be zeroed (documented) |
| WebAssembly linear memory | Until the next job or worker termination | Zeroed after each paste job; worker terminated on Clear and `pagehide` |
| Blob output (file mode) | Until the save, Clear, or `pagehide` | Object URL revoked; Blob reference dropped |
| Clipboard | User-controlled | Written only on an explicit Copy, with sanitized output only |
| Saved files and the browser's download history | User-controlled | The UI states that the browser records the download name |

No application-managed database, cache, history, backup, or audit store exists.

## 12. Integrity architecture

Each invariant names its mechanism and the test that enforces it. Every invariant is a release gate.

| ID | Invariant | Mechanism | Verification |
| --- | --- | --- | --- |
| I-01 | Fail closed: no raw fallback, ever | The core has no fallback path; a `Sanitizer` is poisoned after an error; adapters write only engine output | Fault-injection tests at every error path (§19.6); code review checklist |
| I-02 | Non-target bytes preserved exactly (P-1) | Slice copying from the original line; no re-serialization | Property test of residue equality over random and corpus inputs |
| I-03 | Line structure preserved (P-2) | Separators emitted verbatim; SR-008 keeps body lines | Property test |
| I-04 | Deterministic across platforms and builds (P-3) | No `std`, time, randomness, hash ordering, or floating point | Differential runs, native against WebAssembly and debug against release, on the corpus plus 10⁶ random inputs per CI run |
| I-05 | Idempotent (P-4) | Exact placeholder recognition | Property test |
| I-06 | Chunk-independent (P-5) | Incremental codec and framer, carried CR state | Property test with random and single-byte chunking; fuzz target `stream_split` |
| I-07 | Counts consistent (P-6) | Counts derived from emitted groups | Property test; JSON schema test |
| I-08 | File output complete or absent | §9.3 | Failure injection: full disk via a small tmpfs, permission errors, SIGKILL during writing, which leaves only an orphaned temporary file and an untouched target, and SIGINT and SIGTERM |
| I-09 | Input never modified | Read-only open; same-file refusal | Before-and-after hashes and metadata checks; redirect-over-input documentation test |
| I-10 | Output attributable to a rule set | Compiled-in hash; report and `--version` fields | Release check that the hash in the binary equals the hash of `rules.v1.json` at the tagged commit |
| I-11 | Documentation matches behavior | Docs and `--list-rules` generated from the compiled tables | CI check that a fresh generation shows no diff |
| I-12 | Surfaces are identical (PRD acceptance criteria 7 and 23) | Single engine (ADR-01) | §19.6 parity: CLI against WebAssembly file mode against WebAssembly paste mode, byte-compared over the corpus |
| I-13 | Copy only current sanitized output | Revision-bound snapshot | §19.8 races |
| I-14 | Report reflects reality | `outputComplete` set only after a successful finish and commit | Tests at each failure point |
| I-15 | Release artifacts are the reviewed source | SLSA Build L3 provenance; reproducibility rebuild; signed tags | §14.4 and §14.6 |
| I-16 | Deployed website equals the attested bundle | CI deploys only the attested bundle; a post-deploy hash comparison; SRI | `tools/verify-site` in CI after deploy, and available to users |
| I-17 | Source integrity | Protected branch, required reviews and checks, signed tags, no force-push | Repository rulesets (§15); Scorecard |

## 13. Scalability architecture

Every dimension has a stated design, limit, headroom, and a path for growth that does not break compatibility.

| ID | Dimension | Design | Limit or target | Growth path |
| --- | --- | --- | --- | --- |
| S-01 | Total input size, CLI | Streaming (ADR-04) | Unlimited; memory budget §5.3; acceptance tested at 10 GiB | None needed |
| S-02 | Total input size, browser | Paste: 1 MiB. File mode: Blob up to 1 GiB, or streaming to disk without limit | Release gates §19.9 | A larger Blob limit only after measuring per-browser memory |
| S-03 | Line length | Bounded carry buffer, configurable | Default 1 MiB; maximum 64 MiB | Raising the maximum changes only a limit constant; the algorithm is unaffected |
| S-04 | Throughput, single input | Linear scanners; one automaton pass for triggers; `memchr` | At least 100 MiB/s without matches and at least 30 MiB/s dense, single core | Multi-core processing of one input is a Phase 2 candidate: split at line boundaries and resolve SR-008 state across chunks with a boundary pre-scan. The core API stays unchanged |
| S-05 | Throughput, many inputs | Stateless processes; documented `xargs -P` pattern; container image | Scales linearly with cores and machines | Optional future multi-file mode with `--output-dir` |
| S-06 | Worst-case input | O(N) guarantee (§7.4) | Adversarial throughput at least 25% of the dense-match gate | — |
| S-07 | Start-up | Native binary; rules compiled in; no runtime parsing | Under 50 ms to first output | — |
| S-08 | Rule-catalog growth | Data-driven detector types; single trigger automaton | Added rules raise only the constant factor, within the benchmark gate (§19.9) | New detector types are minor releases of the engine |
| S-09 | Corpus and test growth | Fixtures as data; parallel test execution; nightly long-running jobs (10 GiB, extended fuzzing) | PR CI under 15 minutes | Shard fixture suites |
| S-10 | Platforms | Cross-compiled matrix (§14.2); static musl builds | 7 targets at v1 | Add targets by matrix entry |
| S-11 | Distribution volume | PyPI, GitHub Releases, and a container registry as CDNs; static website on any CDN | No project-run servers | Additional package managers (Homebrew, winget, Scoop) |
| S-12 | Website traffic | Static, immutable assets; no backend; no per-user state | Host bandwidth only | Any CDN satisfying ADR-12 |
| S-13 | Automation adoption | Stable exit codes; versioned JSON report; atomic output; `--list-rules` | Semantic-versioned contracts (§16.4) | Report schema v2 alongside v1 with a deprecation window |
| S-14 | Organizational adoption | Transparent rules; verifiable releases; Baseline evidence | — | Declarative rule packs (Phase 2) using existing detector types; policy packs |
| S-15 | Maintainer load | Automation: Renovate with cooldown, generated documentation, release workflow, issue templates, triage labels | — | Second maintainer and succession plan (§15.3) |
| S-16 | Localization | Strings in one module; no text concatenation | English at v1 | Add locales without code changes |
| S-17 | Integration surfaces | Engine API designed as a reusable library | Internal at v1 | Publish the Rust crate and Python bindings (PyO3) as a later minor feature, without changing the CLI |

## 14. Supply chain and release integrity

### 14.1 Build platform

- Releases are built only on GitHub-hosted, ephemeral runners. Self-hosted runners are not used for release builds.
- The release workflow (`release.yml`) runs on a signed tag `v*` and calls a reusable workflow (`build-reusable.yml`). The reusable workflow builds every artifact and issues the attestations. Because it is the attestation signer, the build instructions are isolated from the calling workflow. This is the documented route to SLSA v1.0 Build Level 3 for GitHub artifact attestations, and it meets the Build L3 "hardened build platform" requirement of SLSA v1.2.
- Release jobs:
  - do not use caches, to prevent cache poisoning;
  - have no long-lived secrets;
  - receive `id-token: write` and `attestations: write` only in the jobs that sign or publish;
  - run with an egress allowlist enforced by a runner-hardening action.
- The workflow verifies the tag signature against the maintainer keys in `.github/allowed_signers` before building. An unsigned or unverifiable tag stops the release.

### 14.2 Targets and artifacts

| Target | Archive | Wheel |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `tar.gz` | `manylinux_2_17_x86_64` |
| `aarch64-unknown-linux-gnu` | `tar.gz` | `manylinux_2_17_aarch64` |
| `x86_64-unknown-linux-musl` (static) | `tar.gz` | `musllinux_1_2_x86_64` |
| `aarch64-unknown-linux-musl` (static) | `tar.gz` | `musllinux_1_2_aarch64` |
| `x86_64-apple-darwin` | `tar.gz` | `macosx_10_12_x86_64` |
| `aarch64-apple-darwin` | `tar.gz` | `macosx_11_0_arm64` |
| `x86_64-pc-windows-msvc` | `zip` | `win_amd64` |
| `aarch64-pc-windows-msvc` | `zip` | `win_arm64` |

#### Other artifacts

- the source distribution, which needs a Rust toolchain to build;
- an OCI image (`linux/amd64` and `linux/arm64`) built `FROM scratch` with the static musl binary, run as non-root UID 65532, with no shell and a read-only root file system;
- the website bundle, `spymonk-redact-web-<version>.tar.gz`, including `build-manifest.json`, which lists every file with its SHA-256;
- `SHA256SUMS`;
- an SBOM per artifact class;
- third-party license notices, generated with `cargo-about` and an npm license tool;
- release notes, including the rule-set version and hash.

**Platform signing.** Windows Authenticode signing and Apple notarization of downloadable binaries are owner decisions (§23), because they need paid certificates. Sigstore provenance and checksums apply whether or not they are adopted. Wheels installed by pip are not subject to download quarantine.

### 14.3 Dependency policy

#### Engine and runtime dependencies

- *Engine:* `memchr`, `aho-corasick`.
- *CLI:* `lexopt`, plus `libc`, `seccompiler`, or `windows-sys` depending on platform. Signal handling is the CLI's own (§9.4), so `ctrlc` and its `nix` dependency are not needed.
- *WebAssembly bindings:* `wasm-bindgen` and `zeroize`.
- *Build-only:* `sha2` and `serde_json`, used inside `build.rs`. They never ship in the binary.
- Any addition requires a written justification in the pull request and a cargo-vet audit or a trusted import of audits from organizations that publish them.

#### cargo-deny policy

- Advisories: deny RustSec vulnerabilities, unmaintained crates, and yanked crates.
- Licenses: allowlist of MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, and Zlib.
- Bans: the networking and process crates listed in §9.8, and duplicate major versions.
- Sources: crates.io only, with no git dependencies.

**Web dependencies.** Only development dependencies: TypeScript, Vite, Vitest, Playwright, axe-core, ESLint, and a CycloneDX npm tool. They are installed with `npm ci --ignore-scripts`. Lockfile integrity hashes are enforced, and `npm audit signatures` verifies registry signatures and provenance where they are available. The production bundle contains no third-party runtime JavaScript beyond the wasm-bindgen glue.

#### Updates

- Renovate opens update pull requests with a minimum release age (cooldown) of 7 days for non-security updates. This guards against compromised releases that are typically discovered and yanked within days.
- Security updates may skip the cooldown after review.
- Third-party GitHub Actions are pinned to full commit SHAs and updated the same way.

### 14.4 Reproducible builds

- **Inputs** are pinned: the Rust toolchain, the Node.js version, the `wasm-bindgen` and `wasm-opt` versions, both lockfiles, `SOURCE_DATE_EPOCH` set to the tag commit time, `--remap-path-prefix`, and `CARGO_INCREMENTAL=0`.
- **Normalization.** Archive creation normalizes file order, timestamps, owners, and permissions (`tar --sort=name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner`). Wheels honor `SOURCE_DATE_EPOCH`.
- **Rebuild gate.** A separate job on a fresh runner rebuilds every artifact from the tag and compares SHA-256 hashes byte for byte. Any mismatch blocks publication. If a target cannot yet be built reproducibly (macOS code-signature padding is a known source of differences), the release notes list it explicitly, and the comparison runs on the unsigned binary.
- **Independent rebuilds.** `tools/repro` documents how anyone can rebuild an artifact and compare it with the published hash.

### 14.5 Signing, provenance, SBOMs, and publishing

| Artifact | Provenance and signature | SBOM | Published to |
| --- | --- | --- | --- |
| Archives, `SHA256SUMS`, web bundle | `actions/attest-build-provenance` (Sigstore keyless, SLSA provenance) | CycloneDX JSON, attested with `actions/attest-sbom` | GitHub Releases |
| Wheels and sdist | Build provenance attestation, plus PEP 740 attestations created automatically by Trusted Publishing through `pypa/gh-action-pypi-publish` | CycloneDX, in the GitHub release | PyPI, from the protected `pypi` environment with OIDC Trusted Publishing and no API token |
| OCI image | Provenance and SBOM attestations, plus a `cosign` keyless signature | CycloneDX, attached as an attestation | GitHub Container Registry |
| Website | Bundle attested as above; deployed only from CI | The bundle's SBOM | Static host, via short-lived OIDC credentials where the host supports them, otherwise a scoped deploy token held only in the `site` environment |

**SBOM format.** CycloneDX JSON, version 1.6 or later as the pinned tooling supports. Version 1.7 is the current ECMA-424 edition. An SPDX export is optional.

**VEX.** OpenVEX statements are published for dependency advisories that do not affect the project.

### 14.6 Verification by users

The install guide gives exact commands for each artifact, with the real organization name filled in at release time.

```sh
# Archives and checksums
gh attestation verify spymonk-redact-1.0.0-x86_64-unknown-linux-musl.tar.gz \
  --repo <owner>/spymonk-redact \
  --signer-workflow <owner>/spymonk-redact/.github/workflows/build-reusable.yml
sha256sum --check --ignore-missing SHA256SUMS

# Container image
gh attestation verify oci://ghcr.io/<owner>/spymonk-redact:1.0.0 --repo <owner>/spymonk-redact
cosign verify ghcr.io/<owner>/spymonk-redact:1.0.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/<owner>/spymonk-redact/\.github/workflows/build-reusable\.yml@refs/tags/v'

# Deployed website against the attested bundle
tools/verify-site https://<domain> --bundle spymonk-redact-web-1.0.0.tar.gz
```

PyPI shows each file's PEP 740 attestation and its publishing workflow. The install guide also documents verifying a wheel's attestation with the PyPA attestation tooling.

Every binary prints its rule-set hash with `--version`. The release notes list the expected hash.

## 15. Project security and governance

### 15.1 Repository controls

#### Default branch ruleset

- Pull request required, with all review conversations resolved.
- Required checks: build, tests, lint, cargo-deny, cargo-vet, CodeQL, zizmor, actionlint, docs-generation diff, and the reproducibility smoke test.
- Signed commits required (squash merges made in the GitHub UI are signed by GitHub).
- Linear history.
- No force pushes and no branch deletion.

**Tag ruleset:** only maintainers may create `v*` tags, and tags must be signed (§14.1).

**CODEOWNERS** covers `/rules/`, `/crates/core/`, `/crates/cli/src/harden/`, `/.github/`, `/web/hosting/`, `/python/`, `/pyproject.toml`, `/deny.toml`, `/supply-chain/`, and `/schemas/`.

**Repository security features:** secret scanning with push protection, Dependabot alerts, private vulnerability reporting, and CodeQL code scanning for Rust, JavaScript/TypeScript, and GitHub Actions.

**OpenSSF Scorecard** runs weekly and on every push to the default branch, and its results are published. Target: no unaddressed applicable check, and an overall score of at least 8.0 at first public release.

### 15.2 Accounts and CI

- All maintainers use phishing-resistant two-factor authentication (passkeys or security keys) on GitHub, PyPI, the website host, and the domain registrar.
- The organization requires 2FA.
- No long-lived registry tokens exist; publishing uses OIDC.

#### Workflow rules

- `permissions: {}` at the top level, with each job granted only what it needs.
- `actions/checkout` with `persist-credentials: false`.
- No `pull_request_target`.
- Fork pull requests run without secrets.
- No workflow interpolates untrusted context, such as PR titles or branch names, into shell commands. zizmor enforces this.

#### Environments

- `release` and `pypi`: a required maintainer approval, and deployment restricted to `v*` tags.
- `site`: a required approval, and deployment restricted to the release workflow.

### 15.3 Maintainers, contributions, and succession

- **Contributions.** `CONTRIBUTING.md` defines the workflow, the toolchain, and the rule-governance checklist (§8.3). Contributions require a Developer Certificate of Origin sign-off, checked in CI. Issue and pull-request templates forbid real secrets or logs, and ask reporters to sanitize with the tool and to use synthetic reproductions.
- **Single-maintainer period.** Independent review cannot exist while only one maintainer is active. Until a second maintainer joins, the compensating controls are:
  - every required automated check;
  - a written release checklist attached to the release pull request;
  - a minimum 24-hour delay between merging the release pull request and pushing the tag;
  - post-release verification by an independent rebuild.

  These limits are recorded in `GOVERNANCE.md`. Baseline controls that assume several maintainers are tracked as known gaps with these compensating controls, not reported as met.
- **Succession.** `GOVERNANCE.md` names a recovery contact for the organization, registry, domain, and host accounts, and documents how maintainers are added and removed.

## 16. Vulnerability management and lifecycle

### 16.1 Intake and scope

`SECURITY.md` and `security.txt` direct reports to GitHub private vulnerability reporting and a project security mailbox (owner decision).

#### In scope

- any raw or unsanitized text exposure;
- a missed detection of a format the documentation lists as supported;
- denial of service through crafted input;
- XSS or DOM injection;
- clipboard exposure;
- sandbox or hardening bypass;
- network activity during processing;
- supply-chain or release integrity issues;
- report content leakage.

**Out of scope:** formats the documentation lists as unsupported, which are welcome as public feature requests; threats listed as out of scope in §11.1.

### 16.2 Handling

- **Response times:** acknowledgment within 3 business days; initial assessment and severity within 7 days. Severity uses CVSS v4.0, adjusted for this product's context.
- **Fix targets** from assessment: Critical within 7 days, High within 30 days, Medium within 90 days, Low in the next planned release.
- **Coordinated disclosure:** an embargo of up to 90 days, extendable by agreement.
- **Advisories:** published as GitHub Security Advisories, with CVE identifiers through GitHub's CNA, and credit to reporters who want it.
- **Fixes** add a regression fixture, or a test for non-detection issues.
- **Review:** a post-incident review for High and Critical issues, recorded in the repository.
- **Dependency advisories:** `cargo audit`, osv-scanner, and `npm audit` run daily on the default branch. Affected releases get patch releases. Unaffected ones get OpenVEX statements.

### 16.3 EU Cyber Resilience Act readiness

The project records its CRA status in `GOVERNANCE.md` (owner decision, §23). For a non-commercial project, manufacturer obligations generally do not apply. If the project is commercial, or later becomes so, these apply:

- reporting actively exploited vulnerabilities and severe incidents through the ENISA Single Reporting Platform: early warning within 24 hours, notification within 72 hours, and final reports on the Regulation's timelines;
- a declared support period;
- free security updates;
- an SBOM;
- technical documentation retained for the period the Regulation requires.

Reporting obligations have applied since 11 September 2026, and the remaining obligations apply from 11 December 2027. The procedure is documented and rehearsed whatever the legal status, so a status change does not create a gap. The essential-requirements mapping is in §17.6.

### 16.4 Versioning and support

#### Three semantic-versioned contracts

- *Tool version:* covers CLI flags, exit codes, output semantics, and browser behavior.
- *Report schema version:* `schemaVersion` integer. Additive fields do not bump it; removals or meaning changes do.
- *Rule-set version:* §8.3.

**Compatibility.** Removing or changing a flag or report field takes at least one minor release of deprecation notice, shown in `--help` and the changelog.

#### Support policy

- Security fixes for the latest minor release.
- The previous minor release is supported for 6 months after a new minor is published.
- Major versions get 12 months of overlap.

The policy is published in `SECURITY.md` and serves as the declared support period.

## 17. Compliance mapping

The repository keeps a machine-readable evidence register (`docs/compliance/evidence.yml`) that links each control to its evidence: a workflow run, a test, a document, or a setting. A compliance self-assessment for each framework is a release gate (§21). The tables below summarize the design-level mapping.

### 17.1 OpenSSF OSPS Baseline (v2026.02.19)

Target: Level 2 at first public release; Level 3 as the maturity goal, with gaps and compensating controls recorded (§15.3).

| Category | Design coverage |
| --- | --- |
| Access control (AC) | Phishing-resistant MFA (§15.2); least-privilege CI; protected branches and tags (§15.1) |
| Build and release (BR) | Pinned dependencies and actions; no untrusted interpolation; signed and attested releases; SBOMs; reproducibility (§14) |
| Documentation (DO) | Install, verification, rules, support policy, and security documentation (§14.6, §16) |
| Governance (GV) | `GOVERNANCE.md`, CODEOWNERS, contribution policy, succession (§15.3) |
| Legal (LE) | License (owner decision), DCO, license allowlist, third-party notices (§14.3, §18) |
| Quality (QA) | Required CI checks, test plan, status checks before merge (§19) |
| Security assessment (SA) | Threat model (§11.1), design review, security testing (§19.11) |
| Vulnerability management (VM) | `SECURITY.md`, private reporting, advisories, dependency scanning, VEX (§16) |

### 17.2 NIST SSDF (SP 800-218 v1.1; the v1.2 draft is tracked)

| Practice group | Implementation |
| --- | --- |
| PO: Prepare the Organization | Security requirements in the PRD and TRD; roles in `GOVERNANCE.md`; toolchain and CI security (§14, §15) |
| PS: Protect the Software | Protected source (§15.1); release integrity through signing, provenance, and checksums (§14.5); archived artifacts and provenance per release (§14.2) |
| PW: Produce Well-Secured Software | Threat-model-driven design (§11); memory-safe language and secure defaults (ADR-01, ADR-11); audited reuse (§14.3); code review and SAST (§15.1); testing including fuzzing (§19); secure build configuration (§4) |
| RV: Respond to Vulnerabilities | Intake, assessment, remediation, advisories, root-cause analysis (§16) |

### 17.3 SLSA v1.2 Build track

| Level | Requirement | Implementation |
| --- | --- | --- |
| L1 | Provenance exists | Attestations for every artifact (§14.5) |
| L2 | Hosted build platform; signed provenance | GitHub-hosted runners; Sigstore-signed attestations |
| L3 | Hardened build platform; isolated builds; signing material inaccessible to build steps | Ephemeral runners; reusable-workflow isolation as the attestation signer; no caches or long-lived secrets in release jobs (§14.1) |

Source-integrity controls (§15.1) cover the source side of the supply chain.

### 17.4 OWASP ASVS 5.0.0, Level 2 (website)

| ASVS area | Applicability | Coverage |
| --- | --- | --- |
| Encoding and Sanitization | Applicable | Text-only rendering, Trusted Types (§10.6) |
| Validation and Business Logic | Applicable | Size and encoding validation; worker message validation (§10.5) |
| Web Frontend Security | Applicable | CSP, Trusted Types, isolation headers, SRI, no third-party resources, external-link handling (§10.6, §10.8, §11.3) |
| File Handling | Applicable (local files) | Local-only file reading, size limits, no execution or rendering of file content (§10.4) |
| Secure Communication | Applicable | HTTPS only, HSTS preload (§11.3) |
| Configuration | Applicable | Header policy, no debug artifacts, no source maps in production, dependency hygiene (§11.3, §14.3) |
| Data Protection | Applicable | No storage, data lifetime controls (§11.4) |
| Secure Coding and Architecture | Applicable | Threat model, least functionality, dependency policy (§11, §14.3) |
| Security Logging and Error Handling | Applicable | Fixed errors; no content logging; no remote logging (§5.5) |
| Cryptography | Limited | No runtime cryptography; SRI and transport only |
| Authentication, Session Management, Authorization, OAuth and OIDC, Self-contained Tokens, API and Web Service, WebRTC | Not applicable | No accounts, sessions, server APIs, or real-time communication |

The full requirement-by-requirement applicability sheet is part of the release evidence.

### 17.5 CWE Top 25 and other relevant weakness classes

| Weakness | Mitigation |
| --- | --- |
| CWE-787, CWE-125, CWE-416, CWE-119 (memory safety) | Safe Rust; `forbid(unsafe_code)` in the engine; audited dependencies |
| CWE-79 (XSS) | Text-node rendering; Trusted Types; CSP |
| CWE-20 (improper input validation) | Codec validation; strict argument and message validation |
| CWE-400, CWE-770, CWE-1333 (resource exhaustion, ReDoS) | Linear detectors; no backtracking engine; limits; memory cap; watchdogs |
| CWE-22 and CWE-59 (path traversal, link following) | Explicit operands only; no-follow create-new temporary files; non-regular outputs refused |
| CWE-367 (TOCTOU) | Handle-based checks |
| CWE-532 and CWE-209 (sensitive data in logs and errors) | Fixed messages; no content in reports; panic hook |
| CWE-150 (escape and control sequence neutralization) | Terminal rendering (§9.5) |
| CWE-200 (information exposure) | Fail-closed design; local-only processing |
| CWE-494, CWE-829, CWE-1357 (untrusted code or components) | SRI; no third-party runtime code; dependency vetting; signed releases |
| CWE-78 and CWE-77 (command injection) | No process execution anywhere (static bans plus seccomp) |
| CWE-352 and CWE-918 (CSRF, SSRF) | Not applicable: no server, no network client |

### 17.6 EU Cyber Resilience Act, Annex I (design alignment)

| Essential requirement theme | Implementation |
| --- | --- |
| No known exploitable vulnerabilities at release | Dependency scanning gates; security testing (§19.11) |
| Secure by default configuration | Defaults: all credential rules on, terminal escaping on, fail closed, no network |
| Protection of confidentiality and integrity of data | Local processing; integrity invariants (§12); atomic output |
| Data minimization | No collection; reports without content |
| Availability and resilience against denial of service | Linear processing; bounded resources (§13) |
| Limited attack surface | No server, network, plugins, or config discovery |
| Logging and monitoring of security-relevant activity | No user activity is logged by design. Release and CI activity is logged on the build platform; local diagnostics are reports only |
| Security updates, separately where feasible | Patch releases; support policy (§16.4) |
| Vulnerability handling, SBOM, coordinated disclosure, advisories | §14.5 and §16 |

### 17.7 Privacy and accessibility frameworks

| Framework | Coverage |
| --- | --- |
| GDPR, Article 25 (data protection by design and by default) | No content processing by the project; minimal hosting logs; privacy notice (§18) |
| ePrivacy (cookies and storage access) | No cookies or client storage, so no consent mechanism is needed |
| WCAG 2.2 AA | §10.7 and §19.10 |

## 18. Privacy and legal

**Privacy position.** The project never receives, processes, or stores user content. The only personal data the project operator handles is ordinary request metadata, such as IP addresses and user-agent strings, that the website host records in access logs.

**Privacy notice.** The website's notice states:

- what the host logs;
- the retention period, configured to the host's minimum and targeted at 7 days or less;
- that no cookies, client storage, analytics, or third parties are used;
- that pasted text and files never leave the device;
- that each visit trusts the host to deliver unmodified code (§11.1, T-10);
- how to contact the operator.

If the host can disable IP logging or truncate addresses, that option is enabled. Hosts whose terms let them inject scripts or analytics into served pages are excluded (ADR-12).

**Licensing.** The license is an owner decision; Apache-2.0 is recommended. Source files carry SPDX license identifiers, following the REUSE specification. Third-party notices ship with every artifact (§14.2). The contribution terms are the DCO (§15.3).

**Names.** Before public install instructions are published, the owner confirms that the publication names `spymonk-redact` (PyPI, crates.io, container registry) and the product name "SpyMonk Redact" are available, and runs a trademark search (§23).

**Export.** The runtime implements no cryptography. SHA-256 is computed only at build time, and transport security is provided by the browser and host.

## 19. Verification plan

None of these tests has run yet, because the product does not exist. All test data is synthetic.

### 19.1 Test layers

| Layer | Tooling | Runs |
| --- | --- | --- |
| Unit and golden corpus | `cargo test`, fixture runner | Every PR |
| Property-based | `proptest` | Every PR (fast profile); nightly (extended profile) |
| Differential (native, WebAssembly, debug, release) | Fixture runner on native and on `wasm32` under Node.js | Every PR |
| Fuzzing | `cargo-fuzz` (libFuzzer); ClusterFuzzLite | Every PR (time-boxed); nightly; OSS-Fuzz once public |
| Mutation testing | `cargo-mutants` on the core crate | Weekly, and before each release |
| Coverage | `cargo-llvm-cov` | Every PR |
| CLI integration | `assert_cmd`; PTY harness | Every PR on Linux, macOS, and Windows |
| Browser unit | Vitest | Every PR |
| Browser end-to-end | Playwright (Chromium, Firefox, WebKit) against the production build served with production headers | Every PR; nightly large-file suite |
| Privacy and network absence | Syscall tracing, binary import inspection, Playwright request and storage auditing | Every PR, plus release |
| Performance and scale | `criterion`, macro benchmarks, memory high-water tests | Every PR (regression signal); release (gate, on the reference machine) |
| Accessibility | axe-core, plus a manual screen-reader checklist | Every PR (automated); release (manual) |
| Security scanning | CodeQL, clippy, ESLint, zizmor, actionlint, cargo-deny, cargo-audit, cargo-vet, osv-scanner, `npm audit signatures` | Every PR, plus daily |
| Release verification | Clean-environment installs; attestation verification; reproducibility rebuild | Every release |

### 19.2 Golden corpus

The corpora are defined in §8.4. The fixture runner compares output bytes, the full summary, the error code, and, where present, the ranges. Every rule ID appears in every expected summary.

### 19.3 Properties

Each property runs over random inputs built from fragments of the corpus, random Unicode text, and inserted triggers:

- residue equality (P-1)
- line structure (P-2)
- determinism across repeated runs (P-3)
- idempotence (P-4)
- chunk independence, with random chunk sizes from 1 byte to 2 MiB (P-5)
- count consistency (P-6)
- range validity: ordered, non-overlapping, and each pointing at a placeholder
- canary absence: no synthetic secret from a positive fragment appears in the output

### 19.4 Fuzzing

#### Targets

- `sanitize_bytes` over arbitrary bytes and options;
- `stream_split`, which processes the same input with arbitrary chunking and asserts equal output;
- `codec`, covering BOMs, UTF-16, and invalid sequences;
- `framer`;
- `manifest_validator`, the build-time validator, run on arbitrary JSON;
- `report_json`, which round-trips the schema.

#### Oracles

- no panic;
- no out-of-memory within the 512 MiB cap;
- no timeout beyond 1 second per MiB of input;
- invariants P-1 to P-6 where checkable.

**Seeds and findings.** The seed corpus is the fixture set. Every finding becomes a regression fixture.

**Release gate.** At least 24 cumulative CPU-hours per target since the last engine change, with no open finding.

### 19.5 Mutation testing and coverage

- Core-crate line coverage of at least 95% and branch coverage of at least 90%.
- `cargo-mutants` catches at least 90% of mutants in `detectors/` and `resolve.rs`. Every surviving mutant is reviewed and either killed with a new test or justified in writing.

### 19.6 CLI, adapter, and parity tests

**CLI integration** (installed binary, run as a subprocess; stdout and stderr captured separately)

- *I/O:* file, stdin, and `-` selection; `--`; an interactive terminal with no file (exit 2); empty input; non-regular input; unreadable input.
- *Encoding:* invalid UTF-8 in both modes; NUL; UTF-16LE and UTF-16BE with a BOM; probable UTF-16 without a BOM; UTF-32 BOMs.
- *Limits:* lines at the limit and one byte over; a 10 GiB stream (nightly) under a memory high-water assertion.
- *Atomic output:* full disk (small tmpfs), permission denied, SIGINT, SIGTERM, and SIGKILL during writing; same-file refusal, including hard links and different path spellings; symbolic-link refusal.
- *Pipes:* broken pipe (exit 141).
- *Reports:* JSON schema validation for success and every failure code.
- *Usage errors:* the user-supplied value is never echoed.
- *Information commands:* `--version`, `--list-rules`, `--help`.
- *Terminal:* PTY rendering of every hidden-character class; byte-exact output when redirected.
- *Windows:* console and redirected output, and CRLF preservation.
- *Platform hardening:* `prctl` and `RLIMIT_CORE` state, and the seccomp filter's presence and effect (an attempted `socket()` from an injected test hook returns `EPERM`).

**Canary checks.** After every test, the combined stdout of failed runs, stderr, the report, and any temporary-directory residue are searched for the synthetic secret canaries and the input path. Any hit fails the test.

**Parity.** For every fixture and for 10⁵ random inputs per run, these must be byte-identical:

- CLI output;
- WebAssembly `sanitize_bytes` output;
- WebAssembly streaming output (file-mode path);
- paste-mode output.

Paste mode is compared after UTF-16 conversion. Its summaries must be equal too.

### 19.7 Privacy and network-absence tests

#### CLI

- On Linux, the full corpus runs under syscall tracing (`strace -f -e trace=%network,%process`, or seccomp in log mode). Zero network or process-creation syscalls are allowed.
- On macOS and Windows, the corpus runs in a network-isolated environment, combined with the binary import check (§9.8).
- The binary import check runs on every release target.

#### Web

- Playwright starts the production build with production headers in a clean context and waits for `ready`.
- It then records every request from the page and the worker while exercising paste, sample load, toggles, Clear, Copy, file mode with both sinks, cancel, timeout recovery, and `pagehide`/`pageshow`.
- Assertions:
  - zero requests after `ready`, apart from an asserted, same-origin re-fetch of the worker script during timeout recovery, if it happens;
  - zero `securitypolicyviolation` events;
  - empty `localStorage` and `sessionStorage`, no IndexedDB databases, no Cache API caches, no cookies, and no service-worker registrations;
  - no input canary in console output, the URL, or the page title.
- The suite repeats with the network disabled after load (PRD acceptance criterion 8).
- An artifact review lists every URL string in the production bundle and fails on any external origin.

### 19.8 Browser end-to-end tests

**Flows and controls:** sample load with confirmation, editing, toggles, Clear, counts and status text, highlighting and the highlight cap, hidden-character badges, the copy toggle and faithful copy, narrow layout, and keyboard-only operation.

**Concurrency and failure:** delayed worker responses to check stale-result rejection; Copy disabled while pending; edit during copy; clipboard denial; worker crash; timeout.

**Rendering safety:** inputs that look like HTML or script are rendered as text, and a Trusted Types violation is asserted for an injected test sink.

**File mode:** Blob and stream-to-disk sinks; cancel; failure partway through, with no save offered and the writable stream aborted; a 1 GiB file (nightly); output byte-identical to the CLI.

**Browser coverage:** the latest two stable desktop releases of Chrome, Edge, Firefox, and Safari at release time, plus automated Chromium, Firefox, and WebKit runs and a manual clipboard and file-mode smoke test on real Safari. Exact tested versions are recorded in the release evidence.

### 19.9 Performance and scale gates

**Reference machine.** Chosen during Milestone 1. Its CPU, RAM, OS, and storage are recorded, along with toolchain and browser versions, the build hash, and the rule-set version.

**Method.** Five warm-up runs, then 30 measured runs per shape, reporting the 50th and 95th percentiles.

#### Input shapes

- no matches;
- sparse matches;
- dense matches;
- Unicode-heavy text;
- long lines at the default limit;
- each adversarial family: repeated triggers, unterminated quotes, delimiter floods, nested URLs, and many `@` characters.

| Gate | Target |
| --- | --- |
| CLI throughput, no matches | ≥ 100 MiB/s, single core, excluding I/O |
| CLI throughput, dense matches | ≥ 30 MiB/s |
| CLI throughput, adversarial families | ≥ 25% of the dense-match figure, and linear: time per byte at 1 GiB within 10% of time per byte at 10 MiB |
| CLI peak RSS | ≤ 24 MiB + 2 × `max_line_bytes`, at 10 GiB input |
| CLI start-up to first output | < 50 ms |
| Paste mode, 100 KiB | 95th percentile ≤ 100 ms, dispatch to rendered result, excluding the 150 ms debounce |
| Paste mode, 1 MiB | 95th percentile ≤ 300 ms |
| File mode throughput | ≥ 20 MiB/s; no main-thread task over 50 ms caused by processing |
| Page weight | JavaScript plus WebAssembly ≤ 400 KiB compressed |
| Timeout recovery | Timeout state within about 2 s of dispatch |
| Rule-change regression | No shape regresses more than 5% without a recorded justification approved in review |

**Regression signal.** Shared-runner CI timings flag regressions of more than 10%. The release gate is measured on the reference machine. A failed gate means optimizing or revising the requirement explicitly. Input, rules, or output are never silently reduced.

### 19.10 Accessibility verification

- axe-core reports zero violations on every state.
- Keyboard-only completion of Flows A and C.
- Manual testing with NVDA and Firefox, and VoiceOver and Safari, against a written checklist that covers the WCAG 2.2 criteria named in §10.7.
- Contrast measured for every theme state.
- Layout checked at 320 px and at 200% zoom.

### 19.11 Security testing

- **Static analysis:** CodeQL (Rust, JavaScript/TypeScript, Actions), clippy with deny-level lints, ESLint with `no-restricted-*` rules for HTML sinks and network APIs, and zizmor plus actionlint for workflows.
- **Dependencies:** cargo-deny, cargo-audit, cargo-vet, osv-scanner, and `npm audit signatures`.
- **Secrets:** repository secret scanning with push protection.
- **Deployed site:** after every deploy, `tools/check-headers` compares the live headers with `headers.json` and checks that no `Set-Cookie` header is present.
- **Binaries:** the import inspection described in §9.8.
- **Independent review.** An independent security review of the engine, CLI hardening, and web surface before 1.0 is recommended. Whether to fund one is an owner decision. Findings are tracked as advisories or issues.

### 19.12 Release verification

For each channel:

- pip, pipx, and uv on every CPython version from 3.11 that is supported at release time, on each operating system;
- the standalone archives;
- the container image.

Each is installed in a clean environment with no source checkout and runs the corpus. Every artifact's attestation is verified in CI with the §14.6 commands. The reproducibility rebuild comparison passes.

## 20. Supportability without telemetry

- `--version`, reports, and the site footer identify the exact build and rule set.
- Bug templates ask for the version line, operating system, options, and a synthetic reproduction, and never for real logs.
- `--list-rules` and the generated rules page answer the question "is this format supported?"
- Documentation includes a troubleshooting page for every error code, for example how to convert BOM-less UTF-16 or raise `--max-line-bytes`.
- No crash reporting, phoning home, or usage counting is ever added. Adoption is measured only through public signals such as release downloads and issues, and through opt-in research.

## 21. Delivery milestones and release gates

### 21.1 Milestones

| Milestone | Scope | Exit criteria |
| --- | --- | --- |
| M0: Foundations | Repository and rulesets; CI skeleton with hardening; toolchain pins; `deny.toml` and cargo-vet; `SECURITY.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`; Scorecard; the license (needs an owner decision) | Required checks enforced; baseline Scorecard result recorded |
| M1: Contracts and engine | Manifest, schema, and `build.rs`; codec; framer; SR-001 to SR-009; resolver; census; corpora; properties; fuzz targets; mutation testing | Corpus gates; P-1 to P-6; 24 clean fuzz CPU-hours per target; adversarial linear gate on the development machine |
| M2: CLI and packaging | CLI; atomic output; rendering; reports and schema; hardening; Python launcher; wheel, archive, and image builds, unsigned at this stage; integration and network-absence tests | §19.6 and §19.7 pass on Linux, macOS, and Windows |
| M3: Browser | WebAssembly bindings; worker; paste and file modes; UI; accessibility; header policy; parity | §19.8, §19.10, and the parity gate pass |
| M4: Hardening and evidence | Reference-machine performance gates; reproducibility; SBOMs; attestation dry runs; compliance self-assessments (Baseline L2, ASVS L2 sheet, SSDF, SLSA); threat-model re-review; install, verify, rules, support-policy, and privacy documentation | Evidence for every release gate recorded in `evidence.yml` |
| M5: Release preparation | After the owner decisions: names reserved, host and domain configured, release workflow wired to PyPI, GHCR, and Releases, site deploy, post-deploy verification | §21.2 gates pass. Public publication is a separate, explicit owner action |

### 21.2 Release gates (all blocking)

1. Every PRD v1.1 acceptance criterion (1 to 24) has recorded passing evidence (§22.2).
2. No open defect that leaks a supported secret, copies raw or stale input, transmits content, writes a partial file as complete, or produces a difference between surfaces.
3. The corpus gates (§8.4) and properties P-1 to P-6 pass.
4. Fuzzing meets §19.4.
5. The performance and memory gates (§19.9) pass on the reference machine.
6. No known exploitable vulnerability in shipped dependencies, or a published VEX statement that the project is not affected.
7. The reproducibility comparison passes, with any exceptions documented.
8. Every attestation verifies with the §14.6 commands.
9. Deployed headers match the policy, and site verification passes.
10. The compliance self-assessments are complete, and Baseline Level 2 is met, with gaps documented as in §15.3.
11. The accessibility gates pass.
12. Documentation is complete, and generated documentation is in sync.

### 21.3 Rollback

- **Website.** Redeploy the previous attested bundle. Old hashed assets are kept for 30 days so that already-loaded pages can finish their start-up. HTML is revalidated on every request.
- **CLI.** Users install the previous version explicitly. A release with a security defect is yanked on PyPI and marked in its GitHub release and advisory.
- No automatic updater exists, and rules never change on users' machines.

## 22. Traceability

### 22.1 PRD review findings to design

| Finding | Closed by | Verified by |
| --- | --- | --- |
| PRV-01 Fixed ceilings | ADR-04; §5.3; §5.4; §10.4; S-01, S-02 | §19.6 10 GiB test; §19.8 1 GiB test |
| PRV-02 Long lines | §5.2 framer; §5.4; S-03 | §19.6 limit tests |
| PRV-03 Performance guarantees | ADR-02; §7.4; §13 | §19.9 |
| PRV-04 Automation contract | ADR-07; §9.6; §9.7; §16.4; S-13 | §19.6 schema and exit-code tests |
| PRV-05 Rule-catalog growth | §8.2; §8.3; S-08 | §19.9 rule-change gate; §8.4 corpora |
| PRV-06 Platforms and channels | ADR-05; §14.2; S-10, S-11 | §19.12 |
| PRV-07 Parity by construction | ADR-01; I-12 | §19.6 parity |
| PRV-08 Failure semantics | ADR-08; §9.3; §9.4; §9.7; I-01, I-08, I-14 | §19.6 failure injection |
| PRV-09 Preservation invariants | §7.2 P-1 to P-6; I-02 to I-07 | §19.3 |
| PRV-10 Verifiable releases and website | ADR-13; §14; I-15, I-16 | §19.12; `tools/verify-site` |
| PRV-11 Rule-set traceability | ADR-03; §8.2; §9.6; I-10, I-11 | §12 checks |
| PRV-12 Threat model | §11.1 | Threat-model re-review in M4 |
| PRV-13 Coverage of common leaks | §6.2, §6.4, §6.5, §6.8 to §6.10 | §8.4 corpora; FX-15 to FX-29 |
| PRV-14 Display-layer attacks | ADR-10; §9.5; §10.2 | §19.6 PTY tests; §19.8 |
| PRV-15 Encoding blind spots | ADR-09; §5.2 codec | Encoding corpus; FX-27 |
| PRV-16 Website trust boundary | ADR-06; ADR-12; §10.6; §10.8; §11.3; T-10 | §19.7; §19.11 header check |
| PRV-17 Project security | §15 | Scorecard; ruleset audit |
| PRV-18 Vulnerability management | §16.1; §16.2 | Process rehearsal before release |
| PRV-19 Compliance baseline | §17 | Self-assessments in M4 |
| PRV-20 EU CRA | §16.3; §17.6 | Status recorded; procedure rehearsed |
| PRV-21 Privacy-law stance | §18; §17.7 | Privacy-notice review |
| PRV-22 WCAG 2.2 | §10.7 | §19.10 |
| PRV-23 Language versus channel | ADR-01; ADR-05; §9.9 | §19.12 pip, pipx, and uv installs |
| PRV-24 Unimplemented optional rule | §6.1 deferred list | UI review: only implemented toggles present |
| PRV-25 Rotation guidance | §9.6 notice; §10.1 and §10.2 UI text | §19.6 and §19.8 notice assertions |
| PRV-26 Measurement targets | §8.4 corpora and gates | §19.2 |
| PRV-27 Lifecycle policy | §16.4 | Published `SECURITY.md` |

### 22.2 PRD v1.1 acceptance criteria to verification

| Criterion | Design | Verification |
| --- | --- | --- |
| 1. Password value | §6.2 | FX-01 |
| 2. Recognized and compound keys | §6.2 | FX-02, FX-15, FX-16, FX-17 |
| 3. Email | §6.6 | FX-07 |
| 4. Home paths | §6.5 | FX-05, FX-06, FX-24, FX-25 |
| 5. URL credentials | §6.4 | FX-04, FX-15 (v1.0), FX-20 |
| 6. Private IP toggle | §6.7 | FX-09, FX-10, FX-14, FX-26 |
| 7. CLI–browser parity | ADR-01; I-12 | §19.6 parity |
| 8. Offline after load | §10.8 | §19.7 offline suite |
| 9. Copy safety | §10.3 | §19.8 races |
| 10. Review notice with rotation guidance | §9.6; §10.2 | §19.6; §19.8 |
| 11. Credential formats | §6.8 | Positive and non-target corpora |
| 12. Private-key blocks | §6.9 | FX-22, FX-23, FX-29 |
| 13. Cookies | §6.10 | FX-18, FX-19 |
| 14. 10 GiB streaming | §5.3; I-06 | §19.6 nightly; §19.9 RSS gate |
| 15. Atomic output and same-file refusal | §9.3; I-08, I-09 | §19.6 failure injection |
| 16. UTF-16 round trip | §5.2 codec | FX-27; encoding corpus |
| 17. Terminal escaping | §9.5 | §19.6 PTY tests |
| 18. Hidden-character census | §5.2; §10.2 | §19.6; §19.8 |
| 19. Line limit | §5.4 | §19.6 |
| 20. JSON report schema | §9.6 | §19.6 schema tests |
| 21. Idempotence | §7.2 P-4 | §19.3 |
| 22. Release verification | §14.6 | §19.12 |
| 23. File-mode parity | §10.4; I-12 | §19.6; §19.8 |
| 24. Linear worst case | §7.4 | §19.9 adversarial gate |

### 22.3 PRD v1.1 non-functional requirements to design

| PRD section | TRD coverage |
| --- | --- |
| 10.1 Privacy | §10.8, §11.4, §18 |
| 10.2 Security and threat model | §9.8, §11 |
| 10.3 Integrity | §7.2, §12, §14 |
| 10.4 Scalability and performance | §5.3, §7.4, §13, §19.9 |
| 10.5 Reliability and failure semantics | §5.5, §9.3 to §9.7 |
| 10.6 Compliance and project security | §14, §15, §17 |
| 10.7 Vulnerability management and lifecycle | §16 |
| 10.8 Accessibility and usability | §10.7, §19.10 |

## 23. Owner decisions and assumptions

| Decision | Recommendation | Blocks |
| --- | --- | --- |
| Approve PRD v1.1 | Approve | Implementation |
| Confirm ADR-01 (Rust engine compiled native and to WebAssembly) | Confirm | Milestone 1 |
| License | Apache-2.0 | M0 exit; contributions; distribution |
| Security contact and mailbox | GitHub private vulnerability reporting plus a dedicated mailbox | Public release |
| Publication identity | Reserve `spymonk-redact` on PyPI, crates.io, and GHCR; trademark search | Public install instructions |
| Hosting provider and domain | A host with per-path headers, no injection, and configurable logs | Website deployment |
| EU CRA status | Record "non-commercial open source" unless monetization is planned | Public release |
| Platform code signing (Authenticode, Apple notarization) | Adopt for standalone binaries if budget allows | Standalone binary distribution |
| Independent security review before 1.0 | Recommended | Optional gate |
| Reference benchmark machine | Implementer selects and records it | M1 |

### Assumptions

- The repository is hosted on GitHub, and CI runs on GitHub Actions, as ADR-13 requires. A move to another forge requires re-validating §14 and §15.
- Exact dependency versions are recorded at implementation time.
- Nothing in this document has been registered, provisioned, or approved beyond what is stated.

## 24. References

- RFC 2119 and RFC 8174, requirement keywords: <https://www.rfc-editor.org/rfc/rfc2119>, <https://www.rfc-editor.org/rfc/rfc8174>
- SLSA specification v1.2: <https://slsa.dev/spec/v1.2/>
- GitHub, using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3: <https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3>
- NIST SSDF, SP 800-218 and the SP 800-218r1 draft: <https://csrc.nist.gov/projects/ssdf/publications>
- OpenSSF OSPS Baseline: <https://baseline.openssf.org/>
- OpenSSF Scorecard: <https://scorecard.dev/>
- OWASP ASVS 5.0: <https://owasp.org/www-project-application-security-verification-standard/>
- CWE Top 25: <https://cwe.mitre.org/top25/>
- Regulation (EU) 2024/2847 (Cyber Resilience Act): <https://eur-lex.europa.eu/eli/reg/2024/2847/oj>
- ENISA, CRA Single Reporting Platform factsheet: <https://www.enisa.europa.eu/sites/default/files/2026-07/ENISA_CRA_SRP_Factsheet_v1.0_0.pdf>
- WCAG 2.2: <https://www.w3.org/TR/WCAG22/>
- RFC 9116 (`security.txt`): <https://www.rfc-editor.org/rfc/rfc9116>
- RFC 1918 (private IPv4): <https://www.rfc-editor.org/rfc/rfc1918>
- RFC 4193 (IPv6 unique-local): <https://www.rfc-editor.org/rfc/rfc4193>
- RFC 4291 (IPv6 addressing): <https://www.rfc-editor.org/rfc/rfc4291>
- RFC 6265 (cookies): <https://www.rfc-editor.org/rfc/rfc6265>
- RFC 7468 (PEM textual encodings): <https://www.rfc-editor.org/rfc/rfc7468>
- PEP 740 (index attestations): <https://peps.python.org/pep-0740/>
- PyPI attestations: <https://docs.pypi.org/attestations/>
- CycloneDX, ECMA-424: <https://ecma-international.org/publications-and-standards/standards/ecma-424/>
- maturin bindings: <https://www.maturin.rs/bindings.html>
- cargo-vet: <https://mozilla.github.io/cargo-vet/>
- cargo-deny: <https://embarkstudios.github.io/cargo-deny/>
- MDN, CSP `require-trusted-types-for`: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for>
- MDN, CSP `connect-src`: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/connect-src>
- MDN, Clipboard `writeText`: <https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText>
- WHATWG File System standard: <https://fs.spec.whatwg.org/>
- Trojan Source (CVE-2021-42574): <https://trojansource.codes/>
- Python version status: <https://devguide.python.org/versions/>
- REUSE specification: <https://reuse.software/>
- Developer Certificate of Origin: <https://developercertificate.org/>
