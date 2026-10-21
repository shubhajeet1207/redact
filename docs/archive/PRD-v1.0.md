> **Archived.** This is a historical record. It was superseded on 21 October 2026; see [docs/](../). Links inside point to other archived v1 documents.

# SpyMonk Redact Product Requirements Document

**Status:** Approved for technical design on 16 October 2026.  
**Approval record:** The project owner reviewed the PRD and PRD review and replied, "looks good to me, go ahead".  
**Technical design:** [TRD](TRD-v1.0.md).

## 1. Product summary

SpyMonk Redact is a local-first developer safety tool that removes sensitive values from technical text before it is shared outside a developer's machine. It accepts logs, stack traces, configuration snippets, command output, and API diagnostics; detects likely secrets and identifiers; then returns a readable, shareable copy with the risky values replaced by clear placeholders.

The first release comprises a Python command-line interface and a browser-based playground. The CLI is the source of truth. The playground demonstrates the same default rule set without sending input to a server.

**Product decision:** The MVP scope is approved. Technical design may proceed using ShareClean as the working name, email redaction enabled by default, private-IP redaction disabled by default, and no telemetry.

**Name change:** On 21 October 2026, before implementation began, the project owner renamed the product from ShareClean to SpyMonk Redact. The CLI command is now `spymonk-redact`, and rule IDs use the `SR-` prefix. The approved scope and defaults are unchanged.

## 2. Problem and opportunity

Developers regularly paste debugging evidence into issue trackers, pull requests, chat tools, support tickets, and AI assistants. That evidence often contains API keys, passwords, access tokens, personal email addresses, database URLs, IP addresses, usernames, and paths that reveal a local identity. Manual cleanup is slow, inconsistent, and easy to skip when debugging is urgent.

Existing secret scanners usually protect repositories or CI pipelines. They do not provide a fast, local, text-in/text-out step at the moment a developer is about to share an excerpt. SpyMonk Redact addresses that gap while preserving the useful structure of the original text.

## 3. Goals

- Let a developer sanitize pasted technical text in seconds, with no account or network dependency.
- Redact the most common accidental disclosures in logs and configuration output while keeping the surrounding diagnostic context readable.
- Make every replacement visible and countable so the user can decide whether the result is safe to share.
- Provide a simple browser demo and an installable CLI with consistent behavior.
- Establish privacy credibility through local execution, no telemetry by default, and transparent rules.

## 4. Non-goals for the MVP

- Guarantee detection of every secret, identifier, or privacy-sensitive string.
- Replace enterprise data-loss-prevention, repository secret scanning, or credential rotation.
- Transmit, store, centrally audit, or synchronize submitted text.
- Inspect files, browser tabs, clipboards, or source repositories automatically.
- Use an LLM or cloud model for detection.
- Build IDE extensions, hosted accounts, teams, billing, or organization policy management.

## 5. Users and jobs to be done

### Primary user: individual developer

When I need to share a log, stack trace, or config excerpt while debugging, I want to remove sensitive values locally and quickly so I can get help without exposing credentials or private information.

### Secondary user: support or platform engineer

When I prepare a reproducible support report, I want a repeatable sanitization command and a replacement summary so I can create a safe artifact without manually editing every occurrence.

### Tertiary user: security-conscious engineering lead

When my team adopts a sharing workflow, I want a tool whose privacy boundary and detection rules are inspectable so I can recommend it without introducing an external data processor.

## 6. Product principles

1. **Local by default.** Input must be processed on the user's device; the MVP must make no network calls for sanitization.
2. **Preserve useful context.** Redact values, not whole lines, unless a rule explicitly requires it.
3. **Make uncertainty visible.** A clean result is not proof that the text is safe. The interface must state this clearly.
4. **Predictable rules.** Default behavior must be deterministic and shared by the CLI and browser playground.
5. **User control.** Users can enable or disable optional rule families and inspect replacement counts.

## 7. MVP scope and requirements

### 7.1 Accepted input

The CLI must accept UTF-8 text from standard input and a file path. The playground must accept pasted text and preloaded demonstration samples. The MVP should support at least 100 KB of input per operation in the browser and 5 MB through the CLI; input beyond the limit must produce a clear error rather than partial output.

### 7.2 Default detection and replacement rules

| Rule family | Examples in scope | Replacement format |
| --- | --- | --- |
| Named secrets | `password=...`, `token: ...`, `api_key=...`, `secret=...` | `[REDACTED]` |
| Authorization credentials | Bearer tokens and Basic credentials in headers | `[REDACTED]` |
| Connection credentials | Password portions of database and service URLs | `[REDACTED]` while retaining host and path |
| Email addresses | Email-shaped strings in diagnostic text | `[EMAIL REDACTED]` |
| Usernames in common local paths | `/home/name/`, `C:\\Users\\name\\` | `[USER]` while retaining the rest of the path |

The default rules must be conservative: they should target high-confidence patterns and avoid removing plain prose or ordinary identifiers. The system must apply all eligible rules deterministically and report the total number of replacements.

### 7.3 Optional rule families

The user can independently enable or disable the following optional rules in the playground and CLI flags:

- Private IP addresses, including RFC1918 IPv4 ranges.
- Additional local identifiers, such as machine names, when supported by a documented rule.

Optional rule status must be visible in the output summary. Rules that are not implemented in the MVP must not be shown as working controls.

### 7.4 CLI requirements

The CLI command name is `spymonk-redact`.

- `spymonk-redact` reads text from standard input and writes sanitized text to standard output.
- `spymonk-redact path/to/log.txt` reads a file and writes sanitized text to standard output.
- `--report` prints a compact replacement summary to standard error without adding it to sanitized output.
- `--enable-private-ip` and `--disable-email` alter the relevant rule families for one execution.
- `--format text` is the MVP default. Structured JSON reporting is deferred unless low-cost to add without changing the default contract.
- Exit code `0` means successful processing, `1` means invalid input or read failure, and `2` means invalid options.
- The CLI must never modify the input file unless a future explicit write option is introduced.

### 7.5 Browser playground requirements

The playground is a static web experience that runs sanitization in the browser.

- A user can select a sample, load it, edit the input, and see sanitized output.
- Input and sanitized output appear side by side with readable monospace formatting.
- The UI shows replacements, lines scanned, and a review indicator based on whether any replacement occurred.
- Toggle controls allow supported optional rules to be changed before processing.
- A Copy output action copies only sanitized output and offers success feedback.
- The page provides links or sections for Playground, Rules, Install, and the source repository.
- The UI explicitly states that the demo is local and that users must still review the result before sharing.

### 7.6 Rules and installation documentation

The product must document each enabled rule family, its example matches, its replacement token, and known limitations. Installation instructions must cover the supported Python version and a basic pipe example.

## 8. User flows

### Flow A: sanitize a log in the browser

1. The user opens the playground.
2. They choose a sample or paste diagnostic text.
3. They set optional rules, if needed.
4. The app processes text locally and shows input, sanitized output, counts, and review status.
5. The user inspects the changed values and copies the sanitized output for sharing.

**Success condition:** the user leaves with a copyable, understandable sanitized excerpt and knows it requires a final human review.

### Flow B: sanitize terminal output with the CLI

1. The user pipes a command or provides a log file to `spymonk-redact`.
2. The CLI prints sanitized text to standard output and replacement information to standard error when requested.
3. The user redirects or copies the standard output into the destination system.

**Success condition:** the user's original data remains unchanged and the sanitized result is useful for troubleshooting.

## 9. Functional acceptance criteria

1. Given `password=super-secret-value`, the output contains `password=[REDACTED]` and increments the count by one.
2. Given an API key assigned with a recognized key name, the output retains the key name and redacts its value.
3. Given an email address with the email rule enabled, the output uses `[EMAIL REDACTED]`.
4. Given `/home/alex/app/config.yml`, the output replaces only `alex` with `[USER]`.
5. Given a connection URL containing user credentials, the output retains the host/database context and redacts the credential portion.
6. With private IP detection disabled, a private IP remains unchanged; with it enabled, it is redacted according to the documented token.
7. The CLI and playground produce the same output for the same text and selected options.
8. The browser can perform sanitization offline after the static assets have loaded.
9. Copy output never copies the unredacted input.
10. The product displays a final-review warning whenever output is shown.

## 10. Non-functional requirements

### Privacy and security

- The MVP must make zero network calls during CLI execution and text processing in the playground.
- The browser app must not persist input, output, or telemetry in local storage, session storage, analytics tools, or remote services by default.
- No input text may appear in application logs, error reports, or crash reporting.
- Dependencies must be pinned and reviewed for unnecessary network behavior.

### Performance

- The playground should process a 100 KB input within 500 ms on a typical modern laptop.
- The CLI should process a 5 MB text file within 2 seconds on a typical developer workstation, excluding disk I/O.
- UI interaction must remain responsive while a normal-sized input is processed.

### Reliability and usability

- Rules must be deterministic and covered by unit tests for positive, negative, and boundary cases.
- Output must preserve line order and line count whenever replacements are inline.
- The UI must work at 320 px viewport width and with keyboard-only navigation.
- Text and status contrast must meet WCAG 2.1 AA for normal text.

## 11. Measurement plan

SpyMonk Redact does not collect product telemetry in the MVP. Adoption and quality will be assessed through opt-in user research, release downloads, issue reports, and locally run test fixtures rather than user-content collection.

Proposed success measures for a pilot:

- At least 90% of evaluated representative samples retain enough context for a reviewer to diagnose the issue.
- No high-confidence secret in the maintained test corpus remains unredacted.
- At least 80% of pilot users can sanitize and copy a sample without assistance in under one minute.
- Zero verified network requests occur during sanitizer execution in automated tests.

## 12. Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| False negatives create false confidence | High | Prominent review warning, transparent rule list, adversarial test corpus, and conservative positioning |
| False positives remove useful debugging context | Medium | Redact only values where possible, retain labels/hosts/paths, and allow optional rule control |
| CLI and web behavior drift | Medium | Shared fixtures and cross-interface parity tests |
| Privacy claim is weakened by a dependency or analytics addition | High | Network-blocking tests, dependency review, and no analytics in MVP |
| Redaction tokens are not understandable to recipients | Low | Use stable, descriptive placeholders and document them |

## 13. Release plan

### Phase 0: rule validation

Build a representative synthetic corpus of logs, config fragments, paths, headers, and URLs. Define expected outputs and review false-positive cases with developers.

### Phase 1: MVP

Deliver the Python CLI, deterministic core rules, static playground, installation guide, rule documentation, unit tests, and browser/CLI parity tests.

### Phase 2: post-MVP candidates

Consider custom user rules, configurable replacement tokens, JSON reporting, file drag-and-drop, an IDE command, additional identifier detectors, and team policy packs. These require separate privacy and product review before commitment.

## 14. Dependencies and open decisions

The product requires a supported Python runtime, a static-site build/deployment path, and an agreed licensing model. The following decisions were open at product approval; the TRD records their resolution or the remaining owner decision:

- Exact Python version floor and packaging method.
- Whether the browser and CLI share a language-independent rule specification or a common runtime implementation.
- Private-IP replacement token and supported address formats.
- License, repository ownership, contribution policy, and security-reporting channel.
- Whether any anonymous update check is ever permitted; the MVP assumption is no.

## 15. Approval checklist

- [x] The local-first and no-telemetry promise is acceptable.
- [x] The defined MVP rule families are the correct first scope.
- [x] The CLI plus browser playground is the desired delivery surface.
- [x] The exclusions and limitations are acceptable.
- [x] The Phase 2 items remain out of MVP scope.

Approval of this PRD authorizes preparation of the Technical Requirements Document. It does not authorize implementation or external deployment.
