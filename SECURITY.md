# Security Policy

SpyMonk Redact is a privacy and safety tool, so we treat security reports as our highest priority.

## Reporting a vulnerability

Report vulnerabilities privately through **GitHub private vulnerability reporting**: open the repository's **Security** tab and choose **Report a vulnerability**. A dedicated security mailbox will be listed here and in `/.well-known/security.txt` before the first public release.

Do **not** open a public issue for a vulnerability, and never include real credentials, real logs, or personal data in a report. Reproduce the problem with synthetic values. You can sanitize your evidence with SpyMonk Redact itself.

## What is in scope

- Any output that contains unsanitized text, or any fallback to raw input
- A missed detection of a format the [rule reference](docs/rules.md) lists as supported
- Denial of service through crafted input (super-linear time, unbounded memory)
- Cross-site scripting or DOM injection in the browser playground
- Clipboard exposure of raw or stale input
- Any network activity during processing, on any surface
- Bypasses of process hardening (seccomp filter, disabled core dumps)
- Supply-chain or release-integrity issues: provenance, signatures, reproducibility
- Reports, errors, or logs that contain input content

Formats the documentation lists as unsupported are not vulnerabilities. Please request them as public feature requests.

## Our commitments

| Stage | Target |
| --- | --- |
| Acknowledge your report | Within 3 business days |
| Initial assessment and severity (CVSS v4.0) | Within 7 days |
| Fix: Critical / High / Medium | 7 / 30 / 90 days from assessment |
| Fix: Low | Next planned release |
| Coordinated disclosure embargo | Up to 90 days, extendable by agreement |

Fixes are published as GitHub Security Advisories with CVE identifiers, and we credit reporters who want credit. Every fix adds a regression test.

## Supported versions

Security fixes are released for the latest minor version. The previous minor version receives security fixes for 6 months after a new minor version is published. No version has been released yet.

## Verifying releases

Every release artifact will carry Sigstore-signed build provenance, an SBOM, and checksums. The steps to verify them are documented in [docs/installation/](docs/installation/README.md).
