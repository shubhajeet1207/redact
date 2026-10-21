> **Archived.** This is a historical record. It was superseded on 21 October 2026; see [docs/](../). Links inside point to other archived v1 documents.

# SpyMonk Redact Technical Design Review

**Reviewed document:** [TRD version 1.0](TRD-v1.0.md)  
**Date:** 16 October 2026  
**Review type:** Author self-review of requirements consistency and design completeness. No implementation or runtime verification was performed.

## Conclusion

The TRD provides an implementable design for the approved Python CLI and browser playground. It resolves the PRD review's technical questions: rule boundaries, runtime parity, copying the current sanitized output, and verification of local processing. No unresolved architecture choice prevents local implementation. Publication identity, license, security ownership, and hosting remain explicit release decisions.

## Ambiguities resolved during review

| Finding | Resolution in the TRD |
| --- | --- |
| The video advertised Python 3.10 without a current support decision | Select 3.11+ based on the current Python support table; review that floor before its end of life |
| The PRD's final-review warning could corrupt piped output | Send the mandatory fixed warning to stderr; keep stdout exclusively sanitized text |
| Overlapping rules could double-count or reveal part of a secret | Detect against original text, merge overlaps deterministically, and count final replacement regions |
| Email detection could interpret a URL password and host as an email | Restrict email matches in URL authorities to the username component |
| Asynchronous browser results could make Copy use stale text | Invalidate immediately on edits/options, require a current revision, and copy only its accepted snapshot |
| A no-network claim could be confused with a website that never loads assets | Define startup requests separately and verify no requests or attempts during processing |
| Regex/runtime behavior and Unicode offsets could differ | Use an explicit grammar, shared expectations, and code-point-normalized result ranges |
| The review indicator could imply a reliable security score | Use descriptive review states; no safety certification or numeric risk score |
| Input limits and line counts lacked precise units | Specify byte ceilings, UTF-8 handling, line separators, and terminal-newline behavior |
| Existing placeholders could count as fresh redactions | Require idempotence for supported formats and exact placeholder recognition |

## Risks that implementation must verify

| Risk | Severity | Required evidence |
| --- | --- | --- |
| Supported secrets survive parsing or overlap handling | High | Reviewed golden corpus, regression fixtures, and non-target preservation tests |
| Two sanitizer implementations drift | High | Full-result parity checks and matching manifest hashes in built artifacts |
| Clipboard races or UI fallbacks expose unintended text | High | Delayed-worker, edit-during-copy, stale-result, and clipboard-denial tests |
| Dependencies or hosting add unintended outbound activity | High | Production artifact review, enforced headers, network-denied tests, and attempted-call instrumentation |
| Regex/scanner behavior becomes slow on large or malformed input | Medium | Maximum-size and adversarial benchmarks on recorded hardware |
| The restricted rule catalog misses formats users assume are covered | Medium | Visible supported-pattern documentation and explicit exclusions using synthetic examples |
| Browser lifecycle and runtime memory retain content longer than expected | Medium | Clear/page lifecycle tests and accurate wording that avoids secure-erasure guarantees |

## Readiness and limits

All ten numbered PRD acceptance criteria map to technical behavior and a verification method. The design has no server-side processing, accounts, LLM calls, or analytics requirement. Hostname detection, public JSON reporting, custom rules, and IDE integration remain outside the MVP.

The documented performance numbers are targets, not benchmarks. The privacy checks are a test plan, not a completed security audit. Public package-name availability and release infrastructure have not been verified or provisioned. Those distinctions must remain visible in subsequent progress reports.

The next authorized stage after a request to implement is Milestone 1 in the TRD. This review does not record a technical approval by the project owner or a public release approval.
