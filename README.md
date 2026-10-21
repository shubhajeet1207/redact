![SpyMonk Redact — Sanitize before you share.](assets/spymonk-redact-banner.svg)

# SpyMonk Redact

**Sanitize before you share. Preserve the context.**

SpyMonk Redact is a planned local-first developer safety tool for removing secrets and personal identifiers from logs, stack traces, configuration snippets, terminal output, and API diagnostics before they leave your device. It is designed for the moment between debugging and sharing: keep the useful evidence, replace the risky values, and review the result before sending it anywhere.

> **Project status — design phase.** This repository currently contains product and technical design documentation only. No CLI, browser playground, package, container image, or hosted service has been implemented or released. The current [PRD](docs/PRD.md) awaits owner approval, and the Rust-plus-WebAssembly architecture decision awaits confirmation.

[Product requirements](docs/PRD.md) · [Technical design](docs/TRD.md) · [Installation & verification status](docs/installation/README.md) · [PRD review](docs/PRD_REVIEW.md)

## The problem

Debugging material often includes credentials, session data, personal email addresses, private paths, and connection strings. Manual cleanup is slow, error-prone, and easy to skip under pressure. Repository scanners help protect source control and CI, but they do not give developers a quick, local text-in/text-out step before pasting an excerpt into a ticket, pull request, chat, support case, or AI assistant.

SpyMonk Redact is designed to fill that gap without turning diagnostic data into another hosted data stream.

## Designed product experience

| Capability | Planned behavior |
| --- | --- |
| **Redact common disclosures** | Detect named secret values, authorization headers, cookie values, credentials embedded in URLs, known token formats, private-key blocks, email addresses, and usernames in home-directory paths. |
| **Keep diagnostics useful** | Replace values rather than entire lines, retaining surrounding logs, structure, field names, schemes, hosts, and paths wherever safe. |
| **Use it where you work** | Provide the same deterministic engine through `spymonk-redact` for terminals and pipelines, and a browser playground for pasted text and local files. |
| **Make findings reviewable** | Show total and per-rule replacement counts, active options, hidden-character warnings, completion state, and a reminder that the output still needs review. |
| **Handle optional privacy rules** | Redact email addresses by default; let users opt into private-IP redaction when their sharing context requires it. |
| **Protect large inputs** | Stream CLI input with bounded memory; the browser design includes pasted-text and local-file modes with progress, cancellation, preview, and save controls. |

## Local by design

The planned product has a deliberately narrow trust boundary:

- Processing happens on the user's device; no account, API server, database, cloud model, telemetry, or update check is part of the product design.
- The browser app is planned as static assets. Once loaded, sanitization is designed to make no network requests and to use no cookies or client storage.
- The CLI is designed to emit sanitized text only to standard output or an explicitly requested output path; reports contain counts and status, never matches or input content.
- The browser and CLI are designed to share one compiled engine and one compiled rule set, so the same input and options yield the same result.

## What it does not promise

SpyMonk Redact is not a guarantee that text is safe to share. It is not a replacement for credential rotation, enterprise DLP, repository secret scanning, or human review. It is also not designed to scan repositories, browser tabs, clipboards, or directories automatically; send data to a cloud service; inspect whether a credential is valid; or accept user-supplied regular expressions.

If a secret has already been exposed, it should be rotated. Every successful planned flow includes that reminder.

## Planned architecture

The current technical design specifies a deterministic Rust core compiled for two surfaces:

```text
stdin / file / pasted text / local file
                │
                ▼
  spymonk-redact-core (Rust, bounded streaming, compiled rules)
                │
         ┌──────┴──────┐
         ▼             ▼
  Native CLI      WebAssembly worker
         │             │
  terminal/files   static browser playground
```

The proposed core has no file, network, process, clock, environment, or logging access. Rules are compiled into the build from a versioned manifest, and detection is designed around linear scanners rather than backtracking regular expressions. See the [TRD](docs/TRD.md) for the security model, release-verification design, performance gates, and test plan.

## Delivery path

| Milestone | Focus |
| --- | --- |
| **M0 — Foundations** | Repository structure, rule-set governance, CI hardening, license and contributor policy decisions. |
| **M1 — Engine** | Streaming sanitizer, codecs, deterministic rule resolution, fixtures, properties, fuzzing, and performance checks. |
| **M2 — CLI & packaging** | Hardened command-line interface, atomic output, reports, Python install channels, archives, and container image. |
| **M3 — Browser** | WebAssembly bindings, worker-based playground, local-file processing, accessibility, and CLI/browser parity. |
| **M4–M5 — Evidence & release** | Reproducibility, SBOMs, attestations, verification guides, deployment checks, and release preparation. |

No milestone should be interpreted as shipped functionality until its release gates have passed.

## Installation and usage

There is **nothing to install yet**. Publication names, release channels, signing, and verification evidence remain owner decisions, and this repository intentionally does not publish speculative `pip install` commands. The planned channels and the conditions for publishing real commands are documented in [Installation & verification status](docs/installation/README.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [Product requirements](docs/PRD.md) | Users, scope, rules, privacy boundaries, acceptance criteria, risks, and owner decisions. |
| [Technical requirements](docs/TRD.md) | The planned Rust/Wasm architecture, security controls, supply-chain design, testing, and delivery gates. |
| [PRD review](docs/PRD_REVIEW.md) | Security, compliance, integrity, and governance findings that informed the current PRD. |
| [Installation & verification status](docs/installation/README.md) | Current release availability and the intended installation and verification channels. |
| [Historical documents](docs/archive/) | Superseded v1.0 PRD, TRD, and reviews. |

## Current repository contents

```text
docs/                  Product requirements, technical design, reviews, and release-planning material
docs/installation/     Canonical installation and verification status
docs/archive/          Superseded design records
assets/                Project banner artwork
```

This project is being designed as an open, inspectable developer-safety tool. Implementation begins only after the outstanding product and architecture decisions are approved.
