# Governance

## Roles

| Role | Holder |
| --- | --- |
| Project owner and maintainer | [@shubhajeet1207](https://github.com/shubhajeet1207) |
| Security triage owner | Project owner, until a dedicated contact is named (see SECURITY.md) |
| Recovery contact for organization, registry, domain, and host accounts | To be named by the owner before the first public release |

Maintainers are added by the owner after sustained, high-quality contributions, and removed on request or after 12 months of inactivity. Every maintainer must use phishing-resistant two-factor authentication (passkeys or security keys) on GitHub, PyPI, the website host, and the domain registrar.

## Decisions

The PRD and TRD in `docs/` are the binding specification. Decisions that change them are recorded as document revisions with a change log.

## Single-maintainer period

Independent review is not possible while only one maintainer is active. Until a second maintainer joins, these compensating controls apply (TRD §15.3):

- Every required automated check must pass before merge.
- A written release checklist is attached to each release pull request.
- At least 24 hours must pass between merging a release pull request and pushing its signed tag.
- After each release, an independent rebuild checks reproducibility.

OpenSSF Baseline controls that assume more than one maintainer are tracked as known gaps with these compensating controls. They are not reported as met.

## EU Cyber Resilience Act status

Status: **non-commercial open-source project**. This is the recommended default and will be confirmed by the owner before release. The project nevertheless follows the CRA essential-requirements alignment in TRD §17.6, and keeps the vulnerability-reporting procedure in TRD §16.3 documented and ready.
