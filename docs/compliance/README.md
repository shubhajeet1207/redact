# Compliance self-assessments

These self-assessments record where SpyMonk Redact stands against the frameworks in [TRD §17](../TRD.md#17-compliance-mapping), before its first release. The machine-readable register is [`evidence.yml`](evidence.yml). Status words mean the same everywhere:

- **Met:** the evidence exists in this repository and passes today.
- **Partial:** evidence exists but does not yet cover the whole requirement.
- **Pending:** the mechanism exists but produces its evidence only at release time.
- **Owner:** an account setting or decision outside the repository.

Nothing here claims a published artifact: no release exists yet.

## OpenSSF OSPS Baseline, Level 2

| Category | Status | Evidence and gaps |
| --- | --- | --- |
| Access control (AC) | Owner | Least-privilege CI is met: every workflow starts from `permissions: {}`, and jobs request only what they need. MFA and branch and tag rulesets are GitHub settings the owner applies ([release runbook](../release.md)). |
| Build and release (BR) | Partial | Actions are pinned by SHA, lockfiles are committed, and untrusted input is never interpolated into scripts. Release workflows build, attest, sign, and rebuild-compare every artifact. These are pending until the first signed tag. |
| Documentation (DO) | Partial | Install status, rule reference, security policy, support policy, privacy notice, and runbook exist. Exact install commands follow name reservation. |
| Governance (GV) | Met | `GOVERNANCE.md`, `CODEOWNERS`, `CONTRIBUTING.md`, and the single-maintainer compensating controls. |
| Legal (LE) | Met | Apache-2.0, DCO check in CI, licence allowlist in `deny.toml`, and the licence shipped in every archive and wheel. |
| Quality (QA) | Met | Required CI: lint, tests on three operating systems in debug and release, web lint, unit and browser tests, supply-chain checks, CodeQL, fuzzing on pull requests. |
| Security assessment (SA) | Met | Threat model in TRD §11, re-reviewed below. Security tests in `crates/cli/tests`, `web/e2e`, and the property suites. |
| Vulnerability management (VM) | Partial | `SECURITY.md`, `security.txt`, and `cargo deny` advisories on every change. Private vulnerability reporting must be enabled in repository settings (owner). |

Gaps that need more than one maintainer are tracked with the compensating controls in `GOVERNANCE.md` and are not reported as met.

## NIST SSDF (SP 800-218)

| Group | Status | Evidence |
| --- | --- | --- |
| PO: Prepare the Organization | Met | PRD and TRD security requirements; roles in `GOVERNANCE.md`; hardened, pinned CI. |
| PS: Protect the Software | Partial | Source protection is an owner setting. Release integrity (provenance, signatures, checksums) is implemented in `release.yml` and pending a tag. |
| PW: Produce Well-Secured Software | Met | Memory-safe Rust with `forbid(unsafe_code)` in the engine; `unsafe` only in audited CLI platform modules; SAST (clippy deny lints, CodeQL); fuzzing; property, parity, and browser tests. |
| RV: Respond to Vulnerabilities | Partial | Process and timelines in `SECURITY.md`; advisories through GitHub. Rehearsal happens before the first release. |

## SLSA v1.2 Build track

| Level | Status | Evidence |
| --- | --- | --- |
| L1: provenance exists | Pending | `actions/attest-build-provenance` for every archive, wheel, image, bundle, and `SHA256SUMS`. |
| L2: hosted build, signed provenance | Pending | GitHub-hosted runners; Sigstore keyless signing. |
| L3: hardened, isolated build | Pending | The reusable workflow `build-reusable.yml` is the only attestation signer; release jobs use no caches and no long-lived secrets; publication runs in separate protected environments. |

## OWASP ASVS 5.0.0, Level 2 (website)

| Area | Status | Evidence |
| --- | --- | --- |
| Encoding and sanitization | Met | Text-node-only rendering; Trusted Types; browser test showing injected markup stays inert. |
| Validation | Met | 1 MiB UTF-8 paste limit measured before dispatch; worker messages validated both ways (`web/src/protocol.ts`, `web/tests/protocol.test.ts`). |
| Web frontend security | Met | CSP, Trusted Types, COOP, COEP, CORP, SRI, no third-party resources (`web/hosting/headers.json`, `scripts/verify-dist.mjs`, browser tests). |
| File handling | Met | Files are read in the worker only; 1 GiB Blob limit; stream-to-disk aborts on failure (`web/tests/worker.test.ts`). |
| Secure communication | Owner | HSTS preload is in the header policy; HTTPS depends on the host. |
| Configuration | Met | No source maps, no debug artifacts, bundle verification, dependency hygiene. |
| Data protection | Met | No storage, no cookies, cleanup on `pagehide` (browser tests). |
| Secure coding and architecture | Met | Threat model, least functionality, dependency policy. |
| Logging and error handling | Met | Fixed error codes; no content in errors or reports. |
| Cryptography | Not applicable | No runtime cryptography; SRI and transport only. |
| Authentication, sessions, authorization, APIs, WebRTC | Not applicable | No accounts, sessions, server APIs, or real-time communication. |

## CWE classes (TRD §17.5)

All mitigations listed in the TRD are implemented. Tests that show them: memory safety (Rust, with `unsafe` confined to platform calls), XSS (browser tests), input validation (codec and protocol tests), resource exhaustion (adversarial linear-growth tests), path traversal and link following (`crates/cli/tests/output.rs`), TOCTOU (handle-based checks), sensitive data in logs (canary checks in every CLI test), escape sequences (`crates/cli/tests/platform.rs`), and command injection (no process execution; seccomp; import checks).

## EU Cyber Resilience Act, Annex I

The project is recorded as non-commercial in `GOVERNANCE.md` (owner to confirm). The design alignment in TRD §17.6 is implemented: secure defaults (all credential rules on, terminal escaping on, fail closed), no network, bounded resources, SBOMs (maturin embeds one in each wheel; `cargo cyclonedx` produces one per artifact class), and a declared support period in `SECURITY.md`.

## Threat model re-review (M4)

| Threat | Status | Implemented mitigations and verification |
| --- | --- | --- |
| T-01 secret outside the grammar | Residual, stated | Rule catalog and coverage limits in `docs/rules.md`; review notice on every run. |
| T-02 parser or overlap defect | Mitigated | Single engine; per-line fixed point (P-4 by construction); properties P-1 to P-6; fuzzing; parity across all surfaces. |
| T-03 super-linear time or unbounded memory | Mitigated | Linear detectors; adversarial linear-growth gate; 512 MiB WebAssembly cap; watchdogs. |
| T-04 terminal escape injection | Mitigated | Escaping on by default for terminals; tested for every hidden class. |
| T-05 hidden characters | Mitigated | Census, notices, `<U+XXXX>` markers in the CLI, badges in the browser; one shared classification (parity test over every code point). |
| T-06 script execution in the playground | Mitigated | Text-only rendering; Trusted Types with a single worker-URL policy; CSP; browser tests. |
| T-07 raw or stale clipboard | Mitigated | Revision-bound Copy (controller tests, browser tests). |
| T-08 compromised dependency exfiltrates | Mitigated | `connect-src 'none'`; seccomp; import checks; strace corpus check; small, pinned dependency set. |
| T-09 compromised CI or account publishes | Partial | Release workflow with tag-signature check, isolated signer, rebuild comparison, protected environments. MFA and rulesets are owner settings. |
| T-10 compromised host serves modified code | Residual, stated | SRI, hashed assets, build manifest with SHA-256 per file, offline bundle. The site verifier is pending host choice. |
| T-11 output file mishandling | Mitigated | Same-file refusal by identity; no-follow, create-new, `0600` temporary file; atomic rename; tests for every case. |
| T-12 content in errors or crashes | Mitigated | Fixed messages; panic hook without payload; core dumps off; canary checks in every CLI test. |
| T-13 browser features leak content | Mitigated | No storage or URL state; `translate="no"`; editor-assistant hints; no prefetch. |
| T-14 typosquatting | Owner | Name reservation on PyPI, crates.io, and GHCR before public instructions. |
| T-15 placeholder-like text | Mitigated | Only exact placeholders are exempt (fixtures). |
| T-16 rules tampered on disk | Mitigated | Rules compiled into the binary; `--version` prints the rule-set hash. |
| T-17 repudiation | Mitigated | Reports carry tool version, rule version and hash, and options; schema-validated in tests. |

New since the TRD was written: the per-line fixed point (T-02), and the Windows process mitigation policies (dynamic-code prohibition, extension-point disablement, strict handle checks), which all apply on current Windows and are reported as `"sandbox": "process-mitigations"`.
