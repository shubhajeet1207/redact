# SpyMonk Redact PRD Review

| Field | Value |
| --- | --- |
| Reviewed document | PRD v1.0, approved 16 October 2026 ([archived copy](archive/PRD-v1.0.md)) |
| Review date | 21 October 2026 |
| Review type | Full review across product, security, compliance, integrity, scalability, reliability, privacy, accessibility, governance, and legal readiness |
| Outcome | 27 findings: 5 blockers, 15 major, 7 minor. Every finding has an amendment in [PRD v1.1](PRD.md). |
| Status | Amendments drafted and applied to PRD v1.1. **PRD v1.1 awaits project-owner approval.** |
| Technical follow-through | [TRD v2.0](TRD.md), designed against PRD v1.1. TRD §22 maps each finding to the design. |
| Supersedes | PRD review v1.0 ([archived](archive/PRD_REVIEW-v1.0.md)), which covered product scope only |

## 1. Why a second review

The v1.0 review checked whether the MVP scope was coherent and passed every technical question to the TRD. It did not test the PRD against a security baseline, release integrity, scaling limits, rule-coverage expectations, or the obligations of running public open-source software. Each of those gaps would eventually appear as an external reviewer's comment, an issue titled "doesn't detect X", or a supply-chain audit failure. This review applies those lenses so that the requirements, not later patches, close the gaps.

## 2. Method

Each lens asks what a competent external reviewer would challenge.

| Lens | Question asked |
| --- | --- |
| Product and scope | Does the scope deliver the stated goals for the stated users, without unimplemented promises? |
| Threat model and security | Are assets, adversaries, and trust boundaries named, and does every requirement trace to a threat? |
| Compliance | Is "secure" measurable against named, current frameworks? |
| Integrity | Can users and recipients rely on the output, the rule set, the release artifacts, and the website being exactly what they claim? |
| Scalability | Which input sizes, throughputs, catalog sizes, platforms, adoption patterns, and maintainer loads break the design? |
| Reliability and failure semantics | What happens on every failure path, and can a failure ever release raw text? |
| Privacy | Does every surface, including hosting, meet the local-first promise and applicable privacy law? |
| Accessibility | Is the target the current standard? |
| Governance and lifecycle | Who maintains, reviews, supports, and responds to vulnerabilities, and on what terms? |

Severity levels:

- **Blocker:** the PRD must change before technical design can be considered complete.
- **Major:** must be resolved before the first public release; the design must account for it now.
- **Minor:** clarity or completeness; resolve before release.

## 3. Verdict

The product intent is sound: local-first processing, no telemetry, value-level redaction that preserves diagnostic context, transparent rules, and honesty about limits. Those principles stay unchanged.

The findings fall into four themes:

1. **Hard ceilings presented as scope.** The 5 MB CLI limit and 100 KB browser limit exist only to guarantee "no partial output". Streaming with fail-closed semantics and atomic file output meets that goal better, without a ceiling. *(Scaling)*
2. **Correctness that depends on testing alone.** Cross-surface parity, output preservation, and failure behavior are stated as outcomes without a mechanism that guarantees them. *(Integrity)*
3. **No threat model, compliance baseline, release-integrity requirement, or vulnerability process.** For a privacy tool, the supply chain is part of the product. *(Security and compliance)*
4. **Coverage misses the credentials developers leak most often**: cloud and source-host tokens, private keys, environment-variable dumps, and session cookies. *(Product credibility)*

No finding challenges the product's reason to exist or its local-first boundary.

## 4. Strengths to retain

- A concrete, urgent user problem with a clear moment of use: just before sharing.
- An explicit privacy boundary: local execution, no storage, and no telemetry, stated as requirements rather than marketing.
- Value-level redaction that keeps labels, hosts, paths, and line structure.
- Honest positioning: a clean result is not proof of safety, and a review warning is mandatory.
- Testable acceptance criteria that can become automated fixtures.
- Non-goals that keep the product away from DLP, repository scanning, and hosted SaaS.

## 5. Findings summary

| ID | Lens | Severity | Finding | PRD v1.1 | TRD v2.0 |
| --- | --- | --- | --- | --- | --- |
| PRV-01 | Scalability | Blocker | Fixed 5 MB / 100 KB ceilings are product limits, not safety limits | §7.1, §10.4 | §5.4, §13 |
| PRV-02 | Scalability | Major | No policy for very long single lines | §7.1, §10.4 | §5.4 |
| PRV-03 | Scalability | Major | No throughput, memory-bound, start-up, or worst-case performance guarantee | §10.4 | §7.4, §13, §19.9 |
| PRV-04 | Scalability | Major | No machine-readable contract for automation and team adoption | §7.4, §10.7 | §9.6, §16.4 |
| PRV-05 | Scalability | Major | No governance or cost bound for growth of the rule catalog | §7.6, §10.3 | §8 |
| PRV-06 | Scalability | Minor | No platform matrix or install channels beyond "installable CLI" | §7.7 | §14.2 |
| PRV-07 | Integrity | Blocker | CLI–browser parity relies on two implementations kept aligned by tests | §6, §10.3 | ADR-01, §12 |
| PRV-08 | Integrity | Blocker | Failure semantics incomplete: partial output, atomic files, output-over-input | §6, §7.4, §10.5 | §9.3, §12 |
| PRV-09 | Integrity | Major | Output-preservation guarantees are informal | §10.3 | §7, §12 |
| PRV-10 | Integrity | Major | No requirement that users can verify genuine releases or the genuine website | §7.7, §10.3 | §14 |
| PRV-11 | Integrity | Major | The rule set that produced an output is not identifiable or verifiable | §7.4, §10.3 | §8, §9.6 |
| PRV-12 | Security | Blocker | No threat model | §10.2 | §11.1 |
| PRV-13 | Security | Blocker | Coverage omits the most frequently leaked credential types | §7.2 | §6 |
| PRV-14 | Security | Major | Terminal control sequences and hidden Unicode can defeat human review | §7.4, §7.5, §10.2 | §9.5, §10.6 |
| PRV-15 | Security | Major | Encoding blind spots, notably UTF-16 from Windows PowerShell | §7.1 | §5.3 |
| PRV-16 | Security | Major | Website trust boundary and hardening not specified | §7.5, §10.2 | §10.8, §11 |
| PRV-17 | Security | Major | No requirements for the project's own security: accounts, branches, CI | §10.6 | §15 |
| PRV-18 | Security | Major | Vulnerability management limited to "define an owner" | §10.7 | §16 |
| PRV-19 | Compliance | Major | No named compliance baseline | §10.6 | §17 |
| PRV-20 | Compliance | Major | EU Cyber Resilience Act applicability not assessed | §10.6, §14 | §16.3, §17.6 |
| PRV-21 | Compliance | Minor | Privacy-law stance implicit; hosting logs not addressed | §10.1 | §18 |
| PRV-22 | Compliance | Minor | Accessibility target is WCAG 2.1, not the current WCAG 2.2 | §10.8 | §10.7 |
| PRV-23 | Product | Major | "Python CLI" fixes an implementation language at product level | §1, §7.4, §7.7 | ADR-01, ADR-05 |
| PRV-24 | Product | Minor | Lists "machine names" as an optional rule with no design | §7.3 | §6.1 |
| PRV-25 | Product | Minor | Accepted "rotate exposed secrets" guidance never entered the PRD | §7.4, §7.5, §9 | §9.6, §10.3 |
| PRV-26 | Product | Minor | Success measures lack false-positive targets and corpus governance | §11 | §8.4, §19 |
| PRV-27 | Governance | Minor | No versioning, support, or deprecation policy | §10.7 | §16.4 |

## 6. Findings in detail

### 6.1 Scalability

**PRV-01: Fixed input ceilings (Blocker).** PRD v1.0 §7.1 caps the CLI at 5 MB and the browser at 100 KB and requires an error above them. Real debugging evidence routinely exceeds both: CI job logs, Kubernetes pod logs, HAR exports, and support bundles are often tens or hundreds of megabytes. A user who hits the ceiling must split the file by hand or skip sanitization, which is the failure the product exists to prevent. The ceiling's only purpose was to avoid partial output. That purpose is better served by (a) streaming, fail-closed processing in bounded memory, (b) atomic writes when output goes to a file, and (c) a status that tells automation whether the output is complete.
*Amendment:* the CLI processes input of any size in memory bounded independently of input size. The browser accepts pasted text up to 1 MiB and processes local files up to 1 GiB, with no size limit where the browser can stream directly to a user-chosen file. Nothing is uploaded.

**PRV-02: Long single lines (Major).** Detection is line-based, so memory scales with the longest line. Minified JSON and single-line structured logs can produce lines of many megabytes. The PRD sets no line limit or behavior.
*Amendment:* a documented, configurable maximum line length (default 1 MiB, adjustable up to 64 MiB) with fail-closed behavior and a specific error.

**PRV-03: Performance guarantees (Major).** v1.0 sets targets only at the two maximum sizes. There is no throughput figure for large inputs, no memory bound, no start-up budget, and no worst-case guarantee. A reviewer can construct input that triggers super-linear regex behavior and present it as a denial-of-service bug, which matters when the tool runs unattended in pipelines.
*Amendment:* throughput and peak-memory targets independent of input size; a linear worst-case processing guarantee for any input; adversarial benchmarks; start-up and bundle-size budgets.

**PRV-04: Automation contract (Major).** v1.0 defers JSON reporting and gives no compatibility promise for flags, exit codes, or report fields. Adoption scales through CI jobs, support tooling, and scripts, which need a stable machine contract.
*Amendment:* a versioned JSON report in the first release, stable exit codes, a rule-listing command, and semantic versioning of the CLI, report schema, and rule set.

**PRV-05: Rule-catalog growth (Major).** Rules will grow, starting with PRV-13. Without governance, each addition risks false positives, performance regressions, and inconsistent semantics.
*Amendment:* every rule carries a documented grammar, a source reference for vendor formats, fixtures, a reviewer, and a changelog entry. Processing cost must stay linear in input size as the catalog grows.

**PRV-06: Platforms and channels (Minor).** "Installable CLI" leaves out environments without Python, containers, ARM machines, and Windows on ARM.
*Amendment:* a supported platform matrix (Windows, macOS, Linux on x86-64 and ARM64) and install channels: Python package installers, standalone archives, and a container image.

### 6.2 Integrity

**PRV-07: Parity by construction (Blocker).** v1.0 requires identical CLI and browser output but leaves the mechanism open. The v1.0 TRD chose two scanners in two languages and rated their drift a High risk. For a tool whose promise is "the same text is redacted the same way everywhere", parity should be guaranteed by construction and confirmed by tests, not produced by tests alone.
*Amendment:* all surfaces use one detection engine. Tests verify that every build of it produces identical results.

**PRV-08: Failure semantics (Blocker).** v1.0 requires "a clear error rather than partial output" but says nothing about output files, interruption, broken pipes, or redirecting output onto the input file. The v1.0 TRD acknowledged that shell redirection can truncate the input and offered no product-level protection.
*Amendment:* a fail-closed principle (never emit unsanitized text, never fall back to raw input); an `--output` option that produces either a complete file or none; refusal to write output onto the input; and a completion status in every report.

**PRV-09: Preservation invariants (Major).** "Readable" and "preserve line order" are informal. Recipients rely on line numbers, column offsets, and exact surrounding bytes to diagnose problems.
*Amendment:* explicit, testable invariants: byte-exact preservation outside replaced spans, line structure preserved, deterministic output, idempotence, and identical results whether input arrives whole or in chunks.

**PRV-10: Verifiable releases and website (Major).** A privacy tool is an attractive supply-chain target: a tampered build could quietly exfiltrate exactly the secrets users feed it. v1.0 has no requirement that users can verify they run genuine artifacts or a genuine website build.
*Amendment:* signed artifacts with build provenance, software bills of materials, reproducible builds, published website asset hashes, and user-facing verification instructions.

**PRV-11: Rule-set traceability (Major).** Output semantics depend on the rule set, but v1.0 does not require reports to identify which rules produced an output.
*Amendment:* every report and version output names the tool version, rule-set version, and rule-set hash. Rule documentation is generated from the same source the engine is built from, so documentation cannot drift from behavior.

### 6.3 Security

**PRV-12: Threat model (Blocker).** v1.0 lists privacy risks but names no assets, adversaries, or trust boundaries. Without them, nobody can judge whether the security requirements are complete.
*Amendment:* a threat-model summary in the PRD (assets, actors, boundaries, explicit exclusions), with the full model in the TRD.

**PRV-13: Coverage of common leaks (Blocker).** The v1.0 default rules miss much of what developers actually paste:

- prefix-identifiable credentials (cloud access keys, source-hosting tokens, package-registry tokens, chat and payment API keys, JSON Web Tokens);
- private-key blocks, including the escaped single-line form inside JSON service-account files;
- environment-variable dumps such as `DB_PASSWORD=` and `GITHUB_TOKEN=`, which v1.0's key boundary rule excluded;
- session cookies in `Cookie` and `Set-Cookie` headers;
- credentials in URLs whose scheme is not on a short list.

A first-time user who pastes an AWS key or a private key and sees it unchanged will not return. The PRD goal "redact the most common accidental disclosures" is unmet.
*Amendment:* new default rule families for known credential formats, private-key blocks, and cookie values; named-secret detection extended to compound keys whose final segment names a secret; URL-credential detection for every scheme; and macOS and JSON-escaped Windows home paths.

**PRV-14: Display-layer attacks on human review (Major).** The product's last safeguard is the user reading the output. Terminal control sequences in a log can rewrite what the terminal shows, and lone carriage returns can overwrite a line on screen. Invisible and bidirectional Unicode characters can make text appear different from what is copied. Either can hide residual sensitive content from the reviewer.
*Amendment:* when output is displayed in a terminal, control characters are shown visibly by default. Both CLI and playground count and flag hidden and direction-changing characters. Redirected output stays byte-exact.

**PRV-15: Encoding blind spots (Major).** Windows PowerShell 5.1 redirection writes UTF-16LE by default. Strict UTF-8 handling would reject such files with no way forward. A byte-level scanner would silently miss every secret in them, because each ASCII character is followed by a zero byte. The PRD's primary users include Windows developers.
*Amendment:* detect and losslessly support BOM-marked UTF-16; detect probable UTF-16 without a BOM and fail with guidance; offer an explicit, reported opt-in for replacing invalid UTF-8 bytes.

**PRV-16: Website trust boundary (Major).** Processing in the playground is local, but every visit trusts the host to serve unmodified code. v1.0 does not state this, specify hardening (content security policy, DOM-injection protection, isolation headers, no third-party resources), or give a higher-assurance path.
*Amendment:* state the trust assumption plainly; require the hardening; publish a verifiable offline bundle; recommend the CLI for highly sensitive material.

**PRV-17: Project security (Major).** Supply-chain reviews check account security, branch protection, required review, CI permissions, and pinned dependencies before they look at code. v1.0 requires none of these.
*Amendment:* project-security requirements covering phishing-resistant two-factor authentication, protected branches, required checks, least-privilege CI, pinned dependencies, and an approval gate for releases.

**PRV-18: Vulnerability management (Major).** v1.0 asks only for an owner. A public security tool needs a coordinated-disclosure policy, a private reporting route, response targets, published advisories with identifiers, a `security.txt`, and a supported-versions policy.
*Amendment:* a vulnerability-management requirement set. Missed detections of supported formats count as security defects.

### 6.4 Compliance

**PRV-19: Compliance baseline (Major).** "Secure" is not measurable without named frameworks.
*Amendment:* adopt current versions of these frameworks and record applicability for each:

- the OpenSSF Open Source Project Security Baseline: Level 2 at first public release, Level 3 as a maturity target;
- NIST SSDF practices;
- SLSA Build Level 3 for release artifacts;
- OWASP ASVS 5.0 Level 2 for the website, where applicable;
- CWE Top 25 weakness classes in design review.

**PRV-20: EU Cyber Resilience Act (Major).** CRA vulnerability-reporting obligations have applied since 11 September 2026; the remaining obligations apply from 11 December 2027. Free, non-commercial open-source software is largely outside manufacturer obligations, but monetization such as paid support or a commercial edition changes that.
*Amendment:* record the project's CRA status as an owner decision, and design to meet the essential requirements regardless: secure defaults, no known exploitable vulnerabilities at release, an SBOM, vulnerability handling, security updates, and a declared support period.

**PRV-21: Privacy-law stance (Minor).** The tool never receives user content. The website host still processes visitor IP addresses in access logs, and v1.0 has no privacy-notice requirement.
*Amendment:* a privacy notice; a hosting choice that minimizes logs and retention; no cookies or client storage, so no consent banner is needed; data-protection-by-design alignment.

**PRV-22: Accessibility target (Minor).** v1.0 targets WCAG 2.1 AA. WCAG 2.2, published October 2023, is the current W3C Recommendation and adds criteria relevant here, including focus not obscured, target size, and an alternative to dragging for the file drop zone.
*Amendment:* WCAG 2.2 AA.

### 6.5 Product, governance, and lifecycle

**PRV-23: Language versus channel (Major).** "Python command-line interface" fixes an implementation language at product level, when the user need is "install it with tools I already have, and run it without runtime dependencies". Fixing the language forecloses the single-engine design that PRV-07 requires.
*Amendment:* a CLI installable with Python package installers (pip, pipx, uv) and as standalone binaries. The TRD chooses the implementation language.

**PRV-24: Unimplemented optional rule (Minor).** §7.3 lists "machine names" as an optional rule, although the PRD itself forbids showing unimplemented controls, and the v1.0 TRD deferred it.
*Amendment:* move it to post-v1 candidates.

**PRV-25: Rotation guidance (Minor).** The v1.0 review recommended telling users that redaction cannot undo a disclosure and that exposed credentials must be rotated. The recommendation was accepted, but the text never entered the PRD body.
*Amendment:* the CLI notice and the playground state it.

**PRV-26: Measurement (Minor).** "No high-confidence secret in the maintained test corpus remains unredacted" does not define the corpus or measure false positives.
*Amendment:* full recall on the supported-grammar corpus; zero changes on the non-target corpus; a tracked change rate on a benign corpus with a release threshold; corpus review rules.

**PRV-27: Lifecycle policy (Minor).** No versioning, support window, or deprecation policy. Users who pin versions, and any CRA support period, need one.
*Amendment:* semantic versioning across the CLI, report schema, and rule set; a security-fix support window; a deprecation notice period.

## 7. Decisions the project owner still needs to make

These do not block design or local implementation. They block public release, and they are not assumed below.

| Decision | Recommendation | Needed before |
| --- | --- | --- |
| Approve PRD v1.1 amendments | Approve as written | Implementation |
| Confirm single-engine architecture (Rust core, TRD ADR-01) | Approve; it closes PRV-01, PRV-03, PRV-07, and PRV-23 together | Milestone 1 |
| License | Apache-2.0 (explicit patent grant, permissive, widely accepted by enterprises) | Accepting contributions or distributing |
| Security contact and triage owner | GitHub private vulnerability reporting plus a dedicated security mailbox | Public release |
| Publication identity | Reserve `spymonk-redact` on PyPI, crates.io, and the container registry; run a trademark search on "SpyMonk Redact" | Public install instructions |
| Hosting provider and domain | A static host with per-path response headers, no injected scripts, and configurable log retention (GitHub Pages cannot set the required headers) | Website deployment |
| CRA status | Record "non-commercial open source" unless monetization is planned | Public release |
| Platform code signing (Apple notarization, Windows Authenticode) | Recommended for downloaded binaries; Sigstore provenance applies regardless | Standalone binary distribution |

## 8. Approval checklist for PRD v1.1

- [ ] The streaming, bounded-memory input model replaces fixed size ceilings (PRV-01, PRV-02).
- [ ] The expanded default rule families are the correct v1 scope (PRV-13).
- [ ] The CLI is defined by install channels, not implementation language (PRV-23).
- [ ] The integrity invariants and fail-closed principle are accepted product requirements (PRV-07 to PRV-11).
- [ ] The threat model, compliance baseline, and vulnerability-management requirements are accepted (PRV-12, PRV-17 to PRV-20).
- [ ] The local-first, no-telemetry promise is unchanged.
- [ ] The post-v1 candidate list remains out of scope.

Approval of PRD v1.1 confirms TRD v2.0 as the design basis. It does not authorize public release.
