> **Archived.** This is a historical record. It was superseded on 21 October 2026; see [docs/](../). Links inside point to other archived v1 documents.

# SpyMonk Redact PRD Review

**Disposition:** Accepted by the project owner on 16 October 2026. The review below is preserved as the product review record. Technical follow-through is documented in [TRD](TRD-v1.0.md) and [TRD review](TRD_REVIEW-v1.0.md).

## Review conclusion

The PRD is suitable for technical design once the five approval items at the end of the PRD are confirmed. It describes a focused, credible MVP: a deterministic local sanitizer, surfaced through a Python CLI and an in-browser playground. The scope matches the video demonstration and avoids promising universal secret detection.

## What is strong
-- action-result-how
- The user problem is concrete and time-sensitive: developers need to share diagnostic text without manually exposing credentials or personal identifiers.
- The privacy boundary is explicit. Local execution, no storage, and no telemetry are product requirements rather than marketing language.
- The requirements preserve debugging value by redacting values while retaining labels, paths, hosts, and surrounding line structure.
- The CLI and playground have a clear parity requirement, which reduces the risk of two conflicting user experiences.
- Non-goals prevent the MVP from becoming an enterprise DLP, repository scanner, or hosted SaaS project.
- Acceptance criteria are testable and can become automated fixtures.

## Gaps that need an approval decision

### Rule catalog depth

The initial rule families are deliberately limited to high-confidence patterns. The final MVP catalog must list exact pattern classes and exclusions before code begins; otherwise contributors may make inconsistent detection choices. The TRD should turn every rule into examples, non-examples, precedence, and replacement behavior.

### Product naming

The project folder and documents use **ShareClean**, matching the video. Confirm this is the preferred working name before identifiers, package names, domains, or visual assets are created.

**Resolution (21 October 2026):** The project owner renamed the product **SpyMonk Redact** (folder and CLI `spymonk-redact`, Python package `spymonk_redact`) before any identifiers, packages, domains, or visual assets were created.

### Browser and CLI parity strategy

Parity is essential but not yet an architecture decision. The TRD needs to select either a shared rule specification with two implementations or one portable sanitizer core. This choice affects testing, packaging, performance, and maintenance.

### Copy safety

The PRD requires Copy output to copy only sanitized text. The TRD should add implementation-level safeguards and tests to prevent stale state, selection mistakes, or UI regressions from exposing the input.

### Privacy verification

The privacy promise is appropriately ambitious. The TRD must define how CI verifies that the playground and CLI perform no network requests, how dependencies are reviewed, and where failure logs are prevented from containing user text.

## Recommended refinements before approval

1. Confirm whether email redaction should be enabled by default. The video shows it enabled; this review recommends keeping that default.
2. Confirm whether private IP redaction is optional. The video presents it as optional; this review recommends retaining that choice because IP addresses can be diagnostically useful in private environments.
3. Decide whether the CLI supports only UTF-8 in the first release. The PRD assumes UTF-8; this is a sensible MVP boundary.
4. Add an explicit statement that users should rotate any secret accidentally published; redaction helps prevent disclosure but cannot undo it.
5. Define an owner for security reports and rule-update triage before public release.

## Approval recommendation

Approve with the open decisions carried into the TRD, provided the product name, default email rule, optional private-IP behavior, and no-telemetry requirement are confirmed. No critical product-scope blocker was found.
