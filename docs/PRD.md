# SpyMonk Redact Product Requirements Document

| Field | Value |
| --- | --- |
| Version | 1.1 |
| Date | 21 October 2026 |
| Status | **Revised; awaiting project-owner approval.** v1.0 was approved on 16 October 2026 ([archived](archive/PRD-v1.0.md)). |
| Changes | Amendments from the [21 October 2026 PRD review](PRD_REVIEW.md); see the change log at the end |
| Technical design | [TRD v2.0](TRD.md) |
| Former name | ShareClean, renamed before implementation on 21 October 2026 |

The keywords MUST, MUST NOT, SHOULD, and MAY are used as described in RFC 2119 and RFC 8174.

## 1. Product summary

SpyMonk Redact is a local-first developer safety tool that removes sensitive values from technical text before it leaves the developer's machine. It accepts logs, stack traces, configuration snippets, command output, and API diagnostics. It detects likely secrets and personal identifiers and returns a readable copy in which the risky values are replaced by clear placeholders.

The first release has two surfaces: a command-line interface, and a browser playground that processes pasted text and local files. The CLI installs with Python package installers (pip, pipx, uv) and as standalone binaries. Both surfaces use one detection engine, so the same input and options always produce the same output.

**Product decisions carried from v1.0:** email redaction is on by default, private-IP redaction is off by default, and there is no telemetry.

## 2. Problem and opportunity

Developers regularly paste debugging evidence into issue trackers, pull requests, chat tools, support tickets, and AI assistants. That evidence often contains API keys, passwords, access tokens, private keys, session cookies, personal email addresses, database URLs, IP addresses, and paths that reveal a local identity. Manual cleanup is slow and inconsistent, and it is easy to skip when debugging is urgent.

Existing secret scanners protect repositories and CI pipelines. They do not provide a fast, local, text-in/text-out step at the moment a developer is about to share an excerpt or a log file. SpyMonk Redact fills that gap while preserving the useful structure of the original text.

## 3. Goals

- Let a developer sanitize pasted text or a log file of any practical size in seconds, with no account and no network dependency.
- Redact the most common accidental disclosures, including widely leaked credential formats and private keys, while keeping the surrounding diagnostic context readable.
- Make every replacement visible and countable, so the user can decide whether the result is safe to share.
- Give identical results across the CLI and the browser.
- Make the tool trustworthy and verifiable: local execution, no telemetry, transparent rules, and releases that anyone can verify.

## 4. Non-goals for v1

- Guarantee detection of every secret, identifier, or privacy-sensitive string.
- Replace enterprise data-loss prevention, repository secret scanning, or credential rotation.
- Transmit, store, centrally audit, or synchronize submitted text.
- Inspect files, directories, browser tabs, clipboards, or repositories automatically.
- Use an LLM, a cloud service, or online validation of credentials for detection.
- Provide IDE extensions, hosted accounts, teams, billing, or organization policy management.
- Accept user-supplied regular expressions.

## 5. Users and jobs to be done

### Primary user: individual developer

When I need to share a log, stack trace, or config excerpt while debugging, I want to remove sensitive values locally and quickly, so I can get help without exposing credentials or private information.

### Secondary user: support or platform engineer

When I prepare a reproducible support report or attach CI logs, I want a repeatable command with a machine-readable summary, so I can produce safe artifacts in scripts and pipelines without editing every occurrence by hand.

### Tertiary user: security-conscious engineering lead

When my team adopts a sharing workflow, I want a tool whose privacy boundary, detection rules, and release provenance can be inspected and verified, so I can recommend it without introducing an external data processor or an unverified binary.

## 6. Product principles

1. **Local by default.** Input is processed on the user's device. Processing makes no network calls.
2. **Preserve useful context.** Redact values, not whole lines. Everything outside a replaced value stays byte-for-byte unchanged.
3. **Fail closed.** On any error, the product never emits unsanitized text and never falls back to the raw input. Output is either complete or clearly marked incomplete.
4. **Make uncertainty visible.** A clean result is not proof of safety. The interface says so and points out anything that could hide content from the reviewer.
5. **Predictable rules.** Behavior is deterministic, versioned, documented from the same source the engine is built from, and identical on every surface.
6. **Bounded by design.** Memory use and processing time scale predictably and never depend on input content in a way an adversary can exploit.
7. **Verifiable.** Users can check that the tool and website they use are the published, unmodified release.
8. **User control.** Users can toggle optional rule families and inspect replacement counts.

## 7. Scope and requirements

### 7.1 Accepted input

- The CLI MUST accept text from standard input or one file path.
- The CLI MUST process input of any size in memory bounded independently of input size, within the line limit below.
- The playground MUST accept pasted text up to 1 MiB.
- The playground MUST process a local file up to 1 GiB without uploading it. Where the browser can stream output directly to a user-chosen file, no total size limit applies.
- Both surfaces MUST enforce a maximum line length: 1 MiB by default, configurable up to 64 MiB. A longer line produces a specific error, and no unsanitized text is emitted.
- UTF-8 is the native encoding. A single leading byte-order mark is accepted.
- UTF-16LE and UTF-16BE input with a byte-order mark MUST be processed losslessly, with output in the same encoding.
- Input that looks like UTF-16 without a byte-order mark, input containing NUL bytes, and invalid UTF-8 MUST produce a specific error with guidance.
- Users MAY opt in to replacing invalid UTF-8 bytes. When they do, the report counts the replacements.

### 7.2 Default detection and replacement rules

| Rule family | In scope | Replacement |
| --- | --- | --- |
| Named secrets | Values assigned to keys whose final segment names a secret: `password=`, `token:`, `api_key=`, `DB_PASSWORD=`, `"client_secret": "..."`, `--password=...` | `[REDACTED]` |
| Authorization headers | Credentials after the scheme in `Authorization` and `Proxy-Authorization` | `[REDACTED]`, scheme retained |
| Cookies | Cookie values in `Cookie` and `Set-Cookie` headers | `[REDACTED]`, names and attributes retained |
| URL credentials | The password in `scheme://user:password@host`, for any scheme | `[REDACTED]`, scheme, user, host, and path retained |
| Known credential formats | Documented, prefix-identifiable tokens, such as cloud access keys, source-hosting and package-registry tokens, chat and payment API keys, and JSON Web Tokens | `[REDACTED]` |
| Private-key blocks | PEM and OpenSSH private-key blocks, multi-line or escaped on a single line | `[PRIVATE KEY REDACTED]`, armor lines and line count retained |
| Usernames in home paths | `/home/<name>/`, `/Users/<name>/`, `C:\Users\<name>\`, including JSON-escaped Windows paths | `[USER]`, rest of path retained |
| Email addresses | Email-shaped strings | `[EMAIL REDACTED]` |

Default rules MUST target high-confidence patterns and avoid altering plain prose or ordinary identifiers. All eligible rules MUST apply deterministically, and the product MUST report the total number of replacements and the count per rule. Each known credential format MUST cite the vendor's published format.

### 7.3 Optional rule families

The user can enable or disable these independently in the playground and with CLI flags:

- Email addresses (on by default)
- Private IP addresses (off by default): RFC 1918 IPv4 ranges and IPv6 unique-local addresses, replaced with `[PRIVATE IP REDACTED]`

The output summary MUST show the status of each optional rule. Unimplemented rules MUST NOT appear as working controls.

### 7.4 CLI requirements

The command name is `spymonk-redact`.

- `spymonk-redact` reads standard input and writes sanitized text to standard output.
- `spymonk-redact path/to/log.txt` reads a file and writes sanitized text to standard output.
- `-o, --output PATH` writes sanitized output to a file. The file is either complete or not created.
- The CLI MUST refuse to write output onto its own input file.
- `--report` prints a summary to standard error. `--report-format json` produces a versioned, schema-validated report. `--report-file PATH` writes the report to a file.
- Every report MUST state whether the output is complete, the tool version, the rule-set version and hash, the options in effect, and the counts. It MUST NOT include matched values, input content, or file paths.
- `--enable-private-ip` and `--disable-email` change the optional rules for one run.
- `--max-line-bytes`, `--input-encoding`, and `--invalid-utf8` control the input behavior in §7.1.
- When standard output is a terminal, control characters and hidden or direction-changing characters MUST be shown visibly by default. Redirected output MUST stay byte-exact.
- `--list-rules` prints the rule catalog in text or JSON.
- `--version` prints the tool version, rule-set version, rule-set hash, and build identity.
- Every successful run prints a fixed notice to standard error: "Review output before sharing; detection is limited. Rotate any credential that was already exposed."
- Exit codes are stable: `0` success, `1` input, processing, or output failure, `2` invalid usage, `130` or `143` interrupted by SIGINT/Ctrl+C or SIGTERM, `141` broken pipe on Unix-like systems.
- The CLI MUST never modify its input file.

### 7.5 Browser playground requirements

The playground is a static web application. All processing runs in the browser.

- **Paste mode:** a user can load a sample, edit input, and see sanitized output side by side in readable monospace text, with inserted placeholders highlighted.
- **File mode:** a user can pick or drop a local file, watch progress, cancel, preview the start of the sanitized output, and save the sanitized file. A save is offered only when processing completed successfully.
- The UI shows replacements, per-rule counts, lines scanned, active options, the rule-set version, and a review status. The review status is never described as "safe".
- Hidden and direction-changing characters in output MUST be shown visibly and counted.
- Toggles control the optional rules.
- Copy output copies only the current sanitized output and confirms success. Copy is never available for stale or incomplete results.
- The page has sections for Playground, Rules (generated from the engine's rule source), Install and verify, Security and privacy, and the source repository.
- The UI MUST state that processing is local, that the user must review the result before sharing, and that already-exposed credentials must be rotated.
- The website MUST load no third-party resources, MUST set no cookies, and MUST use no client storage.

### 7.6 Rules documentation and governance

Each rule family MUST be documented with its grammar, examples, non-examples, replacement token, precedence, and known limitations. This documentation MUST be generated from the same rule source the engine is built from. Adding or changing a rule MUST require:

- positive, negative, overlap, and regression fixtures;
- a source reference for vendor formats;
- a reviewed changelog entry;
- a rule-set version change;
- confirmation that processing cost stays linear in input size.

### 7.7 Distribution and verification

- **Install channels:** Python package installers (pip, pipx, uv), standalone archives, and a container image.
- **Platforms:** Windows, macOS, and Linux on x86-64 and ARM64.
- Every release artifact MUST have a cryptographic signature, build provenance, a software bill of materials, and published checksums. Users MUST have documented steps to verify each one.
- The website build MUST publish the hashes of its assets and a verifiable offline bundle.

## 8. User flows

### Flow A: sanitize pasted text in the browser

1. The user opens the playground and chooses a sample or pastes text.
2. They set the optional rules.
3. The app processes the text locally and shows input, sanitized output, counts, hidden-character warnings, and review status.
4. The user inspects the changes and copies the sanitized output.

**Success:** the user leaves with a copyable sanitized excerpt and knows it needs a final review.

### Flow B: sanitize terminal output or a file with the CLI

1. The user pipes command output, or names a log file, to `spymonk-redact`, optionally with `--output`.
2. The CLI streams sanitized text to standard output or writes the output file atomically, and prints the notice and any requested report to standard error.
3. The user shares the sanitized result.

**Success:** the original data is unchanged and the sanitized result is complete and useful for troubleshooting.

### Flow C: sanitize a large log file in the browser

1. The user switches to File mode and selects a 300 MB log.
2. The app processes it locally with visible progress, and the user can cancel.
3. On completion, the user previews the start of the output and saves the sanitized file.

**Success:** a complete sanitized file is saved locally, and nothing was uploaded.

### Flow D: sanitize artifacts in a pipeline

1. A CI step runs `spymonk-redact build.log --output build.redacted.log --report-format json --report-file redact-report.json`.
2. The pipeline checks the exit code and the report's completion status before uploading the sanitized log.

**Success:** only complete sanitized artifacts are uploaded, and the report gives auditable counts without content.

## 9. Functional acceptance criteria

1. `password=super-secret-value` produces `password=[REDACTED]` and one replacement.
2. A recognized key name, including compound keys such as `DB_PASSWORD`, keeps its name and has its value redacted.
3. With the email rule on, an email address becomes `[EMAIL REDACTED]`.
4. `/home/alex/app/config.yml` changes only `alex` to `[USER]`. The same holds for the macOS and Windows forms.
5. A connection URL with credentials keeps its scheme, user, host, and path, and only the password is redacted.
6. With private-IP detection off, a private IP is unchanged. With it on, it becomes `[PRIVATE IP REDACTED]`.
7. The CLI and the playground produce identical output and counts for the same input and options.
8. The playground keeps working offline once loaded.
9. Copy output never copies unredacted input, a stale result, or an incomplete result.
10. A final-review notice, including rotation guidance, appears whenever output is shown.
11. A synthetic token in each documented credential format is redacted. Strings that resemble a format but violate its documented grammar are unchanged.
12. A private-key block is replaced with `[PRIVATE KEY REDACTED]`, its armor lines are kept, and the line count is unchanged. The escaped single-line form inside JSON is also redacted.
13. Cookie values are redacted and cookie names and attributes are kept.
14. A 10 GiB synthetic input is processed by the CLI within the memory budget. Its output is identical to the output from processing the same input in arbitrary chunk sizes.
15. With `--output`, a failure or interruption leaves no output file and the existing target unchanged. An output path that resolves to the input file is refused before any read.
16. UTF-16LE input with a byte-order mark is redacted and written back as UTF-16LE. Every non-replaced character is identical.
17. Terminal escape sequences and lone carriage returns are shown visibly when output goes to a terminal. Redirected output is byte-identical to the input outside replaced spans.
18. Hidden and direction-changing characters are counted in the report and flagged in the playground.
19. A line over the configured limit causes a specific error, and no unsanitized content from that line is emitted.
20. The JSON report validates against the published schema for both successful and failed runs.
21. A second run over sanitized output makes no new replacements and leaves the text unchanged.
22. The release verification steps succeed on every published artifact.
23. A file processed in the playground's File mode produces output identical to the CLI's for the same file and options.
24. Processing time grows linearly with input size for adversarial inputs designed to trigger worst-case matching.

## 10. Non-functional requirements

### 10.1 Privacy

- The product MUST make no network calls during processing, on any surface.
- The website MUST NOT use cookies, local or session storage, IndexedDB, service-worker caches, analytics, error reporting, or third-party resources.
- Input content MUST NOT appear in logs, error messages, reports, crash output, or URLs.
- The website MUST publish a privacy notice explaining that the host processes ordinary request metadata, such as IP addresses in access logs, and that no submitted content reaches any server.
- Hosting MUST be configured for minimal log retention.
- The product follows data protection by design. Because it uses no cookies or client storage, no consent banner is required.

### 10.2 Security and threat model

**Assets:** the user's input and its secrets; sanitized output; the rule set; release artifacts; the website code.

**Adversaries:**

- the recipient of shared text;
- a malicious or compromised dependency;
- an attacker who compromises a maintainer account, the CI pipeline, or the website host;
- a crafted input that targets automated use, for denial of service, terminal manipulation, or hiding content from the reviewer.

**Trust boundaries:** the user's device; the build and release pipeline; package registries; the website host.

**Out of scope:** a compromised operating system, malicious browser extensions, clipboard managers, screen capture, and the security of any destination where the user shares output.

Requirements:

- No processing code may be able to make network requests, start other programs, or write anywhere other than the requested output.
- Every detector has a linear worst-case cost.
- Input is rendered only as text, never as markup, in every surface.
- The website enforces a strict content security policy, protection against DOM injection, cross-origin isolation, and no third-party resources.
- Users are told that each website visit trusts the host to serve unmodified code. The CLI or a verified offline bundle is recommended for highly sensitive material.

### 10.3 Integrity

- **Single engine.** All surfaces use one detection engine. Tests verify that every build produces identical results.
- **Preservation.** Bytes outside replaced spans are unchanged. Line count and line separators are preserved.
- **Determinism and idempotence.** Identical input, options, and rule set give identical output. Re-processing sanitized output changes nothing.
- **Chunk independence.** Output is identical however the input is split into chunks.
- **Fail closed.** No raw fallback. Output files are atomic, and reports state whether output is complete.
- **Traceability.** Outputs are attributable to a tool version and a rule-set hash.
- **Verifiability.** Release artifacts and the website build can be verified against signed provenance.

### 10.4 Scalability and performance

All targets are release gates, measured on a recorded reference machine.

- **CLI memory:** peak memory stays within a fixed budget regardless of input size. With the default line limit, the budget is 64 MiB.
- **CLI throughput:** at least 100 MiB/s for input with no matches and at least 30 MiB/s for densely matching input, on a single core, excluding disk I/O.
- **CLI start-up:** under 50 ms to first output.
- **Paste mode:** 1 MiB processed within 300 ms (95th percentile) of dispatch, and 100 KiB within 100 ms.
- **File mode:** at least 20 MiB/s, with the page responsive throughout.
- **Website size:** total JavaScript and WebAssembly at most 400 KiB compressed.
- **Worst case:** no input may cause super-linear processing time.
- Adding rules must not change the asymptotic cost.

### 10.5 Reliability and failure semantics

- Every failure produces a fixed, documented error code and message without input content.
- With `--output`, failures and interruptions leave the target untouched.
- When streaming to standard output, a failure stops output at a line boundary, returns a non-zero exit code, and marks the report incomplete.
- Broken pipes, full disks, permission errors, encoding errors, and interruptions are handled without a raw-text fallback and without a stack trace.

### 10.6 Compliance and project security

The project MUST meet, and record evidence against:

- **OpenSSF Open Source Project Security Baseline (OSPS Baseline):** Level 2 at first public release, Level 3 as a maturity target.
- **NIST SSDF (SP 800-218):** its practice groups, tracking the v1.2 revision when it is final.
- **SLSA:** Build Level 3 for all release artifacts.
- **OWASP ASVS 5.0 Level 2:** the requirements applicable to a static, account-less website.
- **CWE Top 25:** design review for the applicable weakness classes.
- **EU Cyber Resilience Act:** record the project's status; meet its essential cybersecurity and vulnerability-handling requirements whether or not the project is legally obligated.

Project-security requirements:

- phishing-resistant two-factor authentication for every maintainer;
- protected default branch with required review and required checks;
- least-privilege CI with pinned third-party actions and dependencies;
- a protected release environment with an approval gate;
- secret scanning with push protection.

### 10.7 Vulnerability management and lifecycle

- **Policy:** a published security policy, private vulnerability reporting, a `security.txt` on the website, and published advisories with CVE identifiers.
- **Response targets:** acknowledgment within 3 business days and an initial assessment within 7 days.
- **Defect scope:** a missed detection of a supported format, or any raw-text exposure, is a security defect.
- **Versioning:** semantic versioning for CLI behavior and flags, the report schema, and the rule set, each stated separately.
- **Support:** security fixes for the latest minor release, and for the previous minor release for six months after a new one.
- **Deprecation:** at least one minor release of notice before removing a flag or report field.

### 10.8 Accessibility and usability

- WCAG 2.2 AA.
- Full keyboard operation, with a file-picker alternative to drag and drop.
- Visible focus that is never obscured.
- Minimum target sizes.
- Status shown in text as well as color.
- Usable at 320 px viewport width.
- UI strings kept separate from code, so localization can be added later.

## 11. Measurement plan

The product collects no telemetry. Quality is measured with maintained corpora and opt-in research.

| Measure | Target |
| --- | --- |
| Supported-grammar positive corpus | 100% of synthetic secrets redacted |
| Non-target corpus (deliberate near-misses) | 0 changes |
| Benign corpus (realistic logs without secrets) | At most 0.5% of lines changed; every change reviewed and justified |
| Cross-surface parity | 100% identical results over the full corpus and randomized inputs |
| Diagnostic usefulness | At least 90% of representative samples keep enough context for a reviewer to diagnose the issue |
| Pilot usability | At least 80% of pilot users sanitize and copy a sample without help in under one minute |
| Network activity during processing | 0 requests or attempts in automated tests |

Corpus fixtures are synthetic and manually reviewed. Expected outputs are never generated by the engine under test.

## 12. Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| False negatives create false confidence | High | Expanded default rules, adversarial corpus, prominent review notice, hidden-character warnings, transparent rule list |
| A tampered release or website exfiltrates secrets | High | Signed provenance, reproducible builds, strict content security policy, no network code, verification steps, offline bundle |
| False positives remove debugging context | Medium | Value-only redaction, benign-corpus threshold, optional rule controls |
| Crafted input causes denial of service in automation | Medium | Linear-time detectors, bounded memory, line limit, fuzzing |
| Surfaces drift apart | Medium | Single engine, cross-build verification |
| Rule growth degrades performance or precision | Medium | Rule governance, performance and benign-corpus gates |
| Placeholders are unclear to recipients | Low | Stable, descriptive, documented placeholders |

## 13. Release plan

**Phase 0: rule validation.** Build the synthetic corpora (positive, non-target, benign), confirm the grammars, and review false positives with developers.

**Phase 1: v1.0.** The detection engine, CLI, browser playground with paste and file modes, versioned reports, rule documentation, install and verification guides, and the compliance evidence required by §10.6. Release artifacts are signed and attested.

**Phase 2: post-v1 candidates.** Each requires its own privacy and product review:

- custom rule packs (declarative, with no user regular expressions);
- configurable placeholder tokens;
- additional identifier detectors, such as machine names and hostnames;
- library APIs;
- IDE commands;
- team policy packs;
- localization;
- multi-core processing of a single input.

## 14. Dependencies and owner decisions

| Decision | Status |
| --- | --- |
| Product name | SpyMonk Redact (resolved 21 October 2026) |
| Email default on; private IP default off | Resolved in v1.0 |
| No telemetry, no update checks | Resolved in v1.0 |
| License | Owner decision; Apache-2.0 recommended |
| Security contact and triage owner | Owner decision, before public release |
| Package and registry names; trademark check | Owner decision, before public install instructions |
| Hosting provider and domain | Owner decision, before deployment; must support per-path response headers |
| EU Cyber Resilience Act status (commercial or non-commercial) | Owner decision, before public release |
| Platform code signing for downloaded binaries | Owner decision, before standalone-binary distribution |

## 15. Approval checklist

- [ ] The local-first, no-telemetry promise is acceptable (unchanged from v1.0).
- [ ] The v1.1 input model and limits are accepted.
- [ ] The v1.1 default and optional rule families are the correct v1 scope.
- [ ] The CLI and browser playground, with paste and file modes, are the desired surfaces.
- [ ] The integrity, security, compliance, and lifecycle requirements are accepted.
- [ ] The Phase 2 items remain out of v1 scope.

Approval of this PRD authorizes implementation against TRD v2.0. It does not authorize public release or deployment.

## Change log

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 16 October 2026 | Approved as ShareClean |
| 1.0 | 21 October 2026 | Renamed to SpyMonk Redact; no scope change |
| 1.1 | 21 October 2026 | Applied PRD review findings PRV-01 to PRV-27: streaming input; expanded rules; single engine; fail-closed and integrity invariants; threat model; compliance baseline; release verification; vulnerability management; WCAG 2.2; CLI defined by install channels |
