> **Archived.** This is a historical record. It was superseded on 21 October 2026; see [docs/](../). Links inside point to other archived v1 documents.

# SpyMonk Redact Technical Requirements Document

**Version:** 1.0  
**Date:** 16 October 2026  
**Product baseline:** [Approved PRD](PRD-v1.0.md) and [accepted PRD review](PRD_REVIEW-v1.0.md)  
**Status:** Technical design prepared and self-reviewed; implementation has not started.  
**Intended readers:** Engineers implementing the CLI, playground, tests, and release process.

## 1. Technical outcome and scope

Build a deterministic text sanitizer with a Python command-line interface and a static browser playground. Both implementations must follow one versioned rule specification and produce identical sanitized text and replacement counts for identical supported inputs and options. The Python implementation is the reference implementation; independently reviewed fixtures define intended behavior and prevent its bugs from becoming the specification.

All sanitization runs on the user's device. No API server, database, account system, cloud model, telemetry, or background update service is required. The website fetches static assets at startup; input processing makes no network requests. Installation and explicit navigation to documentation or a repository are separate from processing.

This document resolves the implementation choices left open in the PRD. It defines planned behavior and verification requirements, not claims that a built product has passed testing. Product approval authorized this design; implementation and public release remain subsequent work.

## 2. Architecture decisions

| ID | Decision | Reason and consequence |
| --- | --- | --- |
| ADR-01 | Python 3.11 or later; standard library only at runtime | Keeps the CLI installable without runtime dependencies. Test the supported stable versions at release time. |
| ADR-02 | TypeScript, semantic HTML, CSS, and Vite for the playground; no UI framework | A single-page input/output tool needs little state and no server rendering. Vite is a development/build dependency. |
| ADR-03 | Shared JSON rule manifest and golden fixtures; separate Python and TypeScript scanners | Avoids a browser Python runtime or native extension while making drift a release-blocking failure. |
| ADR-04 | One dedicated Web Worker for browser sanitization | Keeps expensive scans away from input handling; revision IDs prevent old results from replacing new ones. |
| ADR-05 | Bounded, complete-input processing | Rejects oversized input before producing output; prevents apparent success on truncated data. |
| ADR-06 | Email on, private IPv4 off; all core secret/path rules always on | Matches the approved product defaults. Hostname detection and custom patterns are deferred. |
| ADR-07 | Standard output contains sanitized text only; diagnostics and review warning go to standard error | Preserves pipeline behavior while meeting the PRD's final-review requirement. |
| ADR-08 | Provider-neutral static hosting with HTTPS and configurable response headers | Hosting is required only for public asset delivery. No platform-specific services are needed. |

Python 3.10, shown in the reference video, reached end of life on 1 October 2026. The selected 3.11 floor uses a supported branch; reassess the floor before its scheduled October 2027 end of life. [Python version status](https://devguide.python.org/versions/)

Vite supports a vanilla TypeScript project and production static builds. Select a compatible supported Node.js release and pin exact build/test dependency versions during implementation; Node.js is not needed by CLI users or site visitors. [Vite guide](https://vite.dev/guide/)

## 3. Components and data movement

```text
                       Versioned rule manifest
                         /                \
                 Python package       Browser build
                       |                    |
stdin or file -> CLI adapter -> Python core  |
                       |                    |
              sanitized stdout      input/options -> Worker -> TypeScript core
              report on stderr                           |
                                               current result -> output/copy

            Shared synthetic fixtures test both cores and their adapters
```

The CLI adapter owns byte limits, file reads, encoding, command options, error presentation, and output. The core accepts text and options and returns a result without file, network, clipboard, or logging operations.

The browser controller owns editing state, revision IDs, worker lifecycle, output rendering, and clipboard actions. The worker owns the TypeScript core. It receives text only after local validation and returns sanitized output plus metadata, without a separate original-input field. When no rules match, sanitized output legitimately equals the input.

The shared manifest defines rule IDs, detector types, aliases, defaults, replacement tokens, URL schemes, IP ranges, and precedence. It is data, not executable code or a user-supplied regex language. Both builds embed the manifest. The page does not fetch rule definitions during use.

## 4. Planned repository and build structure

The following is a proposed implementation layout, not a list of files already created:

```text
spymonk-redact/
  README.md
  docs/                       PRD, reviews, TRD, future install/rules guides
  shared/
    rules.v1.json             canonical manifest
    fixtures/                 reviewed inputs, expected outputs, counts
  python/
    pyproject.toml
    src/spymonk_redact/
      __init__.py
      __main__.py
      cli.py
      core.py
      detectors.py
      model.py
      data/rules.v1.json      generated package copy
    tests/
  web/
    package.json
    package-lock.json
    index.html
    src/
      main.ts
      controller.ts
      sanitizer.worker.ts
      core/
      styles.css
    tests/
    e2e/
  tools/                      manifest sync, parity runner, benchmark harness
```

Use `pyproject.toml`, a pinned setuptools build backend, a source layout, and wheel/source distributions. Declare `requires-python = ">=3.11"`, no runtime dependencies, and `spymonk-redact = "spymonk_redact.cli:main"` under `[project.scripts]`. Include the manifest in the wheel and test the installed wheel outside the checkout. Also support `python -m spymonk_redact`. [PyPA packaging guidance](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)

The command name is `spymonk-redact`; the Python import package is `spymonk_redact`. Public package-name availability has not been checked; do not instruct users to install an unrelated package with that name. Use a locally built wheel for development until the publication identity is confirmed.

The build copies the canonical manifest into the Python package and bundles it into the worker. CI compares the generated copy byte-for-byte and checks a manifest hash in both artifacts. Changes to generated copies alone must fail verification. Record app version, rule version, and manifest hash in release metadata; never hash user input for diagnostics.

### 4.1 Manifest validation and versioning

The manifest has `schemaVersion` (initially integer 1), `ruleVersion` (initially `1.0.0`), and an ordered `rules` array. Each rule records its unique ID, a supported detector type, default-enabled flag, replacement token, unique precedence rank, and detector-specific data such as aliases, schemes, or IP ranges. Reject unknown detector types, missing or duplicate IDs, duplicate precedence, invalid ranges, and unsupported schema versions. A malformed manifest must stop startup; never run with a silently reduced rule set.

The numbered rule catalog in section 6 defines the initial manifest contents and detector semantics. Use rule-version patch increments for fixes restoring this contract, minor increments for deliberately expanded detection, and major increments for changes to existing replacement/default semantics. Record every output-affecting change in the changelog with fixture differences. Package and rule versions are distinct but pinned together in each artifact.

## 5. Input and result contracts

### 5.1 Limits and encoding

| Surface | Accepted input | Maximum | Oversize behavior |
| --- | --- | --- | --- |
| CLI | Strict UTF-8 from stdin or one regular file | 5 MiB, exactly 5,242,880 bytes | Exit 1, empty stdout, fixed error on stderr |
| Browser | Text from the editor or a bundled sample | 100 KiB, exactly 102,400 UTF-8 bytes | Invalidate output, disable Copy, show limit and actual size |

The binary limits intentionally meet or exceed the PRD's 5 MB and 100 KB minimums. The raw CLI limit includes an optional UTF-8 BOM. Read at most the limit plus one byte; do not trust file metadata alone. Reject directories and special-file operands. Stream input is allowed through stdin. Process only after EOF; do not emit partial results while reading.

Reject invalid UTF-8, NUL characters, and unpaired Unicode surrogates. A single leading BOM is accepted and removed by both cores; document this normalization. Otherwise preserve characters, spaces, order, and line endings outside replacement spans. Preserve a missing final newline. Do not interpret literal backslash escapes as characters: the two characters `\n` do not create a new line.

Use actual CRLF, LF, and lone CR as line separators. Define `linesScanned` as zero for empty text; otherwise the number of separators plus one when the final character is not a separator, treating CRLF as one separator. Thus `a\n` with an actual final LF is one line and `a\n\n` is two.

Browser textarea editing can normalize newlines. Parity compares the exact string delivered to the core, not the clipboard's original byte representation; Windows CLI file processing must retain CRLF bytes. Browser size validation counts UTF-8 bytes, not JavaScript string length. Check obvious oversize before creating unnecessary copies and avoid retaining the encoded byte buffer.

### 5.2 Core interfaces

Equivalent interfaces in the two languages:

```text
sanitize(text, options, limits, includeRanges = false) -> SanitizeResult

Options:
  email: boolean = true
  privateIp: boolean = false

Limits:
  maxInputBytes: positive integer, supplied by the adapter

SanitizeResult:
  sanitizedText: string
  replacements: integer >= 0
  linesScanned: integer >= 0
  countsByRule: mapping of rule ID to integer >= 0
  options: resolved Options
  ruleVersion: string
  findings: list of Finding, when includeRanges is true

Finding:
  outputStart: integer
  outputEnd: integer
  ruleId: string
```

Finding ranges are half-open Unicode code-point offsets into sanitized output. They identify inserted placeholders only, not unchanged existing placeholders. Python uses code-point indexes; TypeScript converts its UTF-16 indexes at the result boundary using a linear pass. Emoji and combining-character fixtures must catch offset errors. Browser rendering may use these ranges to highlight inserted tokens. CLI runs with ranges disabled.

The CLI supplies a 5,242,880-byte limit and the worker supplies a 102,400-byte limit. The core validates UTF-8 size before removing the optional BOM; adapters perform earlier checks to avoid unnecessary reads or worker messages. These are internal interfaces, not a committed public library API.

Result metadata contains no original matched values, context snippets, reversible mappings, secret hashes, or input paths. Sanitized text can still contain material outside the detection grammar. The UI already owns its input; do not duplicate it in result metadata. Counts include every replaced occurrence rather than distinct secret values. A repeated secret on two lines produces two replacements. The sum of per-rule counts must equal the total after overlap resolution. Return all six rule IDs in `countsByRule`, including zero for disabled or unmatched rules, to make parity comparison unambiguous.

### 5.3 Error contract

The core either returns a complete result or a structured error code; it never returns the original input as a fallback. Supported codes are `INVALID_TEXT`, `INPUT_TOO_LARGE`, `INVALID_OPTIONS`, `RULESET_INVALID`, and `PROCESSING_FAILED`. Adapters add `INPUT_READ_FAILED`, `OUTPUT_WRITE_FAILED`, `WORKER_UNAVAILABLE`, and `PROCESSING_TIMEOUT` as appropriate.

Messages are fixed strings with safe numeric details such as the byte limit. Do not interpolate input, user-provided filenames, unknown argument values, exception messages, or stack traces. Invalid options must be rejected even when passed programmatically.

## 6. Detection rules and boundaries

All matching is deterministic, line-bounded, and independent of locale. Rule names and aliases use ASCII case folding. No entropy detector, provider lookup, network validation, decoding of nested documents, or user pattern execution is included.

### 6.1 Rule catalog

| ID | Enabled | Target | Replacement |
| --- | --- | --- | --- |
| SR-001 | Always | Values assigned to recognized secret keys | `[REDACTED]` |
| SR-002 | Always | Basic/Bearer credential in a recognized authorization field | `[REDACTED]` |
| SR-003 | Always | Password component in recognized URL user information | `[REDACTED]` |
| SR-004 | Always | Username component of a supported home-directory path | `[USER]` |
| SR-005 | Default on | Supported email-shaped address | `[EMAIL REDACTED]` |
| SR-006 | Default off | RFC1918 IPv4 address | `[PRIVATE IP REDACTED]` |

### 6.2 Named secret values

SR-001 aliases are exactly `password`, `passwd`, `pwd`, `api_key`, `api-key`, `apikey`, `token`, `access_token`, `refresh_token`, `secret`, and `client_secret`. Match a complete key, optionally enclosed in matching single or double quotes, followed by optional spaces/tabs, `:` or `=`, and optional spaces/tabs. The preceding character must be absent or outside ASCII letters, digits, underscore, hyphen, and dot. This excludes substrings such as `password_length`, `my_password`, and `object.password`.

A quoted value extends to the matching unescaped closing quote on the same line; honor backslash-escaped quotes when locating its boundary, but do not decode its content. Redact the inside and retain both quotes. For an unterminated quoted value, redact through the end of that line and retain the opening quote. An unquoted value ends at whitespace, comma, semicolon, ampersand, hash, a quote, or a JSON bracket/brace. Preserve those delimiters. Empty values do not count as replacements. Multiline strings, arrays, and objects are not traversed as assigned values; independently detectable patterns inside them may still match.

Recognize a complete reserved placeholder as an atomic value before applying those delimiters; this allows placeholders containing spaces to survive a second run. A marker embedded inside a larger value is not an exemption. Any parser ambiguity involving a supported key must be represented by a fixture rather than resolved differently by the two runtimes.

### 6.3 Authorization fields

SR-002 recognizes complete `Authorization` and `Proxy-Authorization` field names, case-insensitively, with the same optional key quotes and assignment separators as SR-001. The field value may be quoted. Retain the `Basic` or `Bearer` scheme and its following whitespace, replacing the nonempty credential token. The credential ends at whitespace or the enclosing quote/delimiter; `=` padding is part of a Basic token. Do not decode Basic credentials or parse JWT contents.

Recognize an existing reserved placeholder as the complete credential without increasing the count. Unsupported schemes such as Digest, bare tokens without a recognized key/header, and authentication cookies are not covered by this rule.

### 6.4 URL passwords

SR-003 recognizes these schemes: `postgres`, `postgresql`, `mysql`, `mariadb`, `mongodb`, `mongodb+srv`, `redis`, `rediss`, `http`, `https`, `amqp`, and `amqps`. Match the scheme followed by `://`. A URL candidate ends at whitespace, a quote, or an angle bracket. Its authority ends at `/`, `?`, or `#`.

Within the authority, use the last raw `@` to separate user information from the host. The first colon in user information separates the username from the password. Replace the nonempty password through that `@`, excluding the delimiter itself. Retain scheme, username, host, port, and subsequent path/query/fragment unless another rule targets a separate part. An empty username is allowed. Percent-encoded bytes within the password are redacted without decoding. Reserved delimiters in credentials must be percent-encoded to be supported reliably.

Do not reserialize URLs using a general URL parser: doing so can change case, escaping, or spacing. Do not redact a host's port or the colons in an IPv6 host as credentials. URLs containing user information without a password separator are outside SR-003 coverage. When a URL is itself the value of `secret=...`, SR-001 can replace the entire value.

Email detection inside a recognized URL authority is limited to the username component. It must not mistake the password-to-host `@` delimiter for an email address and remove the host. With email enabled, an email-shaped username is separately redacted; with email disabled, it remains. Private-IP detection can redact an eligible URL host when enabled.

### 6.5 Usernames in paths

SR-004 supports `/home/<user>/...` and a Windows drive-letter path such as `C:\Users\<user>\...`, also allowing consistent forward slashes in the Windows form. Linux prefix matching is case-sensitive; Windows prefix matching is ASCII case-insensitive. Require a separator after the username and at least one username character. Redact only the username segment.

For unquoted paths, accept username characters from letters, digits, underscore, hyphen, and dot. For a whole path enclosed in matching quotes on one line, permit spaces and other Unicode characters in the username except separators, quotes, and controls. Escaped backslash representations inside serialized JSON, macOS `/Users/...`, UNC paths, `~`, and arbitrary occurrences of a person's name are outside this rule's MVP coverage. No filesystem access occurs.

### 6.6 Email addresses

SR-005 covers a pragmatic ASCII subset: a local part of letters, digits, `.`, `_`, `%`, `+`, and `-`, followed by `@`, followed by a dotted domain. Domain labels contain letters, digits, and internal hyphens; the final label contains 2 to 63 ASCII letters. Reject leading/trailing or repeated dots in the local part, invalid label edges, and invalid token boundaries. Surrounding punctuation remains unchanged.

Quoted local parts, Unicode email addresses, address literals, and single-label domains are excluded. This is a documented detection grammar, not an assertion of complete email-address validation. Do not redact a partial substring of an unsupported address. Turning the email rule off does not prevent SR-001 from redacting an email used as a password value.

### 6.7 Private IPv4 addresses

SR-006 accepts exactly four decimal octets from 0 to 255, with no leading zeros except the single digit `0`. Redact only addresses inside `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. These are the private address blocks in RFC1918. [RFC1918](https://www.rfc-editor.org/rfc/rfc1918.html)

Require token boundaries so `110.0.0.1`, `10.0.0.256`, and portions of dotted hostnames cannot match accidentally. Preserve a following port or CIDR suffix. Public IPv4, loopback, link-local, shared carrier space, IPv6, and integer/hexadecimal IP encodings are excluded. Use the explicit ranges in both runtimes rather than a library's broader or changing definition of a private address.

### 6.8 Coverage limits

Private keys, arbitrary free-floating secrets, encoded payloads, nested escaped logs, hostname detection, multiline credentials, and custom rules are deferred. Existing placeholders do not prove that nearby content is safe. Sanitization does not neutralize terminal control sequences or guarantee the validity of a copied JSON/config document. Users must inspect the output; credential revocation or rotation after disclosure is outside the sanitizer's capabilities.

## 7. Matching, overlap resolution, and preservation

Each detector emits candidate ranges against the original line. Do not run one replacement pass over text already modified by another detector. Validate every range as nonempty and within the input. Preserve the original separator between lines.

Apply the following algorithm separately to each line, accumulating aggregate counts and output:

1. Find structural URL regions needed to disambiguate email candidates, then collect all enabled rule candidates.
2. Discard candidates whose complete target is already one of the four reserved placeholders. Do not exempt a larger containing value.
3. Sort candidates by start position, then end position. Form connected groups of strictly overlapping ranges; touching ranges remain separate.
4. For an isolated candidate, use its rule's replacement token. For multiple candidates covering an identical range, use precedence SR-001, SR-002, SR-003, SR-004, SR-005, SR-006.
5. For an overlapping group with differing ranges, redact the entire union with `[REDACTED]`. Attribute the one replacement to the highest-precedence rule in the group. This avoids restoring part of a candidate another rule identified.
6. Emit unchanged slices and replacement tokens once, left to right. Count final replaced regions and, when requested, compute output ranges.

Consequences: `password=alex@example.com` becomes `password=[REDACTED]` with one SR-001 replacement. Two distinct occurrences count twice. A second run with identical options must leave the output unchanged and produce zero new replacements for supported formats. No rule changes surrounding whitespace or line endings as a side effect.

Use bounded token scanners or simple precompiled patterns. Avoid nested unbounded regex repetition and repeated whole-document substitutions. The fixed number of rule passes should scale with input length; sorting overlapping candidates adds `O(k log k)` per line for `k` matches. Long single lines and repeated delimiters must be benchmarked. Do not silently truncate findings or skip later lines to satisfy a time target.

## 8. CLI behavior

### 8.1 Command surface

```text
spymonk-redact [FILE|-] [--report] [--enable-private-ip] [--disable-email]
           [--format text] [--help] [--version]
```

No file operand or `-` selects stdin. One file operand selects a regular file; multiple operands are invalid. Support `--` before a filename beginning with a hyphen. No recursive scan, wildcard expansion by the application, in-place write, clipboard access, or configuration discovery is included. `--format` accepts only `text` in the MVP; JSON output is explicitly deferred.

When stdin is an interactive terminal and no file is selected, show a fixed usage hint and exit 1 instead of waiting indefinitely. An empty piped stream or empty file is a valid result. An explicit file operand is never opened for writing. File permissions and contents must remain unchanged.

Example commands are prospective local usage after installation:

```sh
spymonk-redact application.log --report
spymonk-redact application.log --enable-private-ip > application.sanitized.log
spymonk-redact - --disable-email --format text
```

Shell redirection is controlled by the shell; redirecting back to the input filename can truncate it before the CLI starts. Installation documentation must use distinct input/output names and explain that limitation.

### 8.2 Output and diagnostics

Write the fully sanitized text as UTF-8 bytes with no added newline or color codes. Use binary streams for redirected input/output to avoid locale encoding and newline translation. Windows interactive-console behavior must be tested independently from redirected byte output.

Every successful sanitization writes the fixed warning `Review output before sharing; detection is limited.` to stderr, satisfying PRD acceptance criterion 10 without polluting stdout. `--report` adds aggregate lines such as:

```text
spymonk-redact: replacements=3 lines=4 email=on private_ip=off rules=1.0.0
spymonk-redact: SR-001=2 SR-004=1
Review output before sharing; detection is limited.
```

Print nonzero per-rule counts in rule-ID order; include `none` for zero replacements. Reports never include matched values or filenames. `--help` and `--version` are informational commands and do not print a review warning. Version output includes app and rule versions. Invalid argument handling must override any parser defaults that echo argument contents.

| Exit | Meaning | stdout behavior |
| --- | --- | --- |
| 0 | Successful processing, help, or version | Complete sanitized text, or requested informational text |
| 1 | Input, validation, runtime, or output failure | Empty for all failures before output begins |
| 2 | Invalid CLI options | Empty |
| 130 | User interruption | No newly generated diagnostic content containing input |

Catch broken pipes and encoding/write failures without a traceback. A write failure or interruption after writing starts may leave a prefix of already-sanitized output; stdout is not transactional. Never fall back to raw text. Zero replacements still means successful processing, not a guarantee that no secrets exist.

## 9. Browser behavior and concurrency

### 9.1 Layout and controls

Provide the landing overview, Playground, Rules, Install, and a repository link once its actual destination is confirmed. Keep the two text panels side by side on wide viewports and vertically stacked on narrow viewports. Use a labelled editable textarea, a read-only output panel, a sample selector with Load, email/private-IP toggles, Copy output, and Clear.

Use bundled synthetic samples for an API log, configuration excerpt, and stack trace. Samples must never contain working credentials or real personal data. Confirm before replacing nonempty user-edited input with a sample. Clear explicitly discards editor/output state and restores default toggles without writing to the clipboard.

Show total replacements, lines scanned, active options, and rule version. Use text states such as `No matches found — review before sharing` and `3 replacements — review before sharing`. Do not label zero matches `safe`, use a percentage risk score, or infer a security rating from the replacement count. The reference video's colored bar is not a calibrated score.

### 9.2 State and worker protocol

States are `initializing`, `empty`, `pending`, `ready`, `error`, and `unavailable`. Input is disabled until the worker and all required static assets have initialized. Workers communicate using structured messages; the selected API supports worker-to-page messaging and termination. [Web Worker documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers)

```text
Request:
  type: sanitize
  revision: monotonically increasing integer
  text: string
  options: Options

Success:
  type: result
  revision: integer
  result: SanitizeResult

Failure:
  type: error
  revision: integer
  code: fixed error code
```

On every edit, sample load, or option change, increment the revision synchronously, clear the accepted result, and disable Copy. Empty input enters `empty` with zero counts and no new scan; nonempty input enters `pending`. Debounce dispatch by 150 ms. Permit one request in flight and one latest pending request; replace an older pending request rather than enqueueing every keystroke. Ignore returned results whose revision does not match current state.

Validate size and text before dispatch; invalid text enters `error` without a request. The worker independently validates the contract and input limit and requests output ranges from the core. A response must match revision, options, and the bundled rule version before becoming `ready`. Clearing input invalidates results and queued requests immediately; a running worker may finish its bounded scan, but its stale response is discarded. A timeout or crash of that worker still requires recovery before another scan.

If a dispatched scan takes more than 2 seconds, terminate the worker, clear pending data/results, and show a timeout with Copy disabled. A worker crash or initialization failure produces `unavailable`. In the MVP, recovery is a page reload or use of the CLI; do not fall back to a server or repeatedly download/restart workers during input processing. No result is displayed as complete after timeout.

### 9.3 Copy behavior

Enable Copy only when a nonempty accepted result belongs to the current revision and options. At click time, recheck those conditions and capture the sanitized string. Call `navigator.clipboard.writeText` directly within the user action; do not wait for a new scan or read from the input panel. The Clipboard API requires a secure context and can reject access. [Clipboard writeText documentation](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText)

Display `Copied sanitized output` only after the write promise resolves. If the user edits while the write is pending, the previously validated snapshot may finish copying, but do not label the new revision as copied. On failure or unsupported access, preserve the result and offer selection of the read-only output for manual copying. Do not read the clipboard, request clipboard access on load, auto-copy on each keystroke, or automatically erase the user's clipboard.

### 9.4 Rendering and accessibility

Insert input-derived content only through text nodes or textarea values, never HTML interpretation. Display any highlight spans using created DOM elements and code-point-correct ranges; never construct markup with string interpolation of input. Keep the output text available for normal selection.

Provide explicit labels, visible focus, keyboard access, and a polite live status region that announces a completed update rather than every keystroke. Apply the PRD's WCAG 2.1 AA text contrast target; communicate status using text as well as color. At 320 px, the document must not overflow horizontally; long code lines may scroll inside their panel. Preserve input focus during result updates.

## 10. Privacy boundary and operational security

### 10.1 Data lifetime

Input and output exist in process memory, the page DOM, and worker messages as necessary. Do not use local/session storage, IndexedDB, cookies, URL query/fragment state, session replay, analytics, console logging of content, error uploads, service-worker caches, or automatic download/history features. No persistence of preferences is required for MVP.

Release references to old inputs/results when superseded. Clear known UI state on `pagehide`; clear restored state on `pageshow` and initialize a fresh worker if necessary before accepting input. Use `autocomplete="off"`, disable spellcheck/autocorrect on the editor, and do not promise that browser or OS features obey these preferences. Garbage-collected runtimes cannot guarantee immediate secure erasure. Clipboard history, browser extensions, screen recording, swap, and OS crash dumps are outside application control.

User-triggered Copy intentionally writes sanitized output to the OS clipboard. CLI stdout and user-requested shell redirection are deliberate output destinations. No application-managed database, backup, recovery history, or content audit store exists.

### 10.2 Website delivery

Serve production assets from the same origin over HTTPS, including scripts, worker code, CSS, icons, and samples. Use system fonts. Eagerly initialize required assets before enabling editing. Bundle manifest/sample JSON, and avoid lazy imports that could fetch code in response to pasted content. An already-loaded page must work offline; a first visit or cold reload while offline is not promised. A downloaded site can be served locally; direct `file://` execution is not a supported installation mode.

Require a production response-header policy equivalent to:

```text
Content-Security-Policy:
  default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
  font-src 'none'; connect-src 'none'; worker-src 'self';
  object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

Apply an appropriate restrictive policy to the worker script response as well. Emit external CSS and script files; avoid inline styles/scripts that require weakening the policy. The `connect-src` directive covers interfaces such as fetch, WebSocket, and sendBeacon; it is one control, not proof that every possible browser request is prevented. Audit resource loads and user-triggered navigation separately. [CSP connect-src documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/connect-src)

Do not configure CSP reporting, remote error collection, hosting analytics injection, or marketing tags. Keep input out of every URL. Hosting providers can see ordinary page/asset request metadata; the public site's privacy wording must distinguish that from processing content. External repository links use a fixed URL and no referrer. Disable automatic link previews/prefetch for external links.

The development server can make build-tool connections. Privacy tests must target a production build served with production headers, not a hot-reload session. Use synthetic content in development and CI.

### 10.3 CLI and dependency boundary

The shipped Python runtime imports no networking client, subprocess runner, or update checker for processing. It reads only the selected input plus its packaged rule data, and writes only stdout/stderr. Never read environment variables looking for secrets. Build/install tools may require downloads, but no install/build component is invoked by `spymonk-redact` during sanitization.

Lock development dependencies, review install scripts and transitive additions, verify generated artifacts, and run dependency audits during development/release preparation. No third-party code may add content logging or remote execution to the runtime. Static review, instrumentation, and a network-denied integration environment together verify the intended boundary.

## 11. Verification and acceptance plan

Use pytest for Python unit/integration tests, Vitest for TypeScript units, and Playwright for the production browser flow. These are development dependencies. Pin versions and browser binaries in the implementation environment. This section specifies future tests; none have run because the application does not yet exist.

### 11.1 Shared golden corpus

Each JSON fixture has a stable ID, input string, resolved options, expected output, total count, per-rule counts, line count, and optional expected output ranges or error code. Expected outputs are reviewed manually; they must not be regenerated blindly from the reference implementation.

Minimum fixture families include every alias and scheme, positive/negative boundaries, quoting/escaped quotes, empty and malformed values, mixed rule overlap, all four option combinations, repeated secrets, reserved placeholders, non-ASCII text/emoji, BOM, CRLF/LF/CR, no final newline, exact byte limits, invalid text, and long adversarial lines.

Illustrative normative examples, all using synthetic values:

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
| FX-15 | `postgresql://app:fake-pass@db.example/app` | Default | `postgresql://app:[REDACTED]@db.example/app` | 1 |

Cross-runtime tests must compare all result fields for the common input domain, not output alone. Property tests cover determinism, idempotence under unchanged options, unchanged non-target spans, count consistency, valid ordered output ranges, and line-ending preservation. Test construction must distinguish a supported format from a deliberately excluded one.

### 11.2 Adapter and end-to-end tests

CLI tests execute an installed wheel as a subprocess and capture stdout/stderr separately. Cover file/stdin selection, noninteractive empty input, terminal-without-file behavior, option errors without argument echo, read permission failure, invalid UTF-8, NUL, oversized streams, output failure, version/help, Windows line endings, and unchanged input files. Verify errors never reproduce synthetic secret canaries or user-supplied paths.

Browser tests exercise sample loading, editing, toggles, Clear, counts, output highlighting, live announcements, narrow layout, and keyboard use. Delay worker responses deliberately to verify stale-result rejection, disabled Copy while pending, edit-during-copy behavior, timeout, crash, and clipboard denial. Assert copied text equals the current accepted sanitized snapshot and that no input panel or stale result is used accidentally. Test HTML/script-shaped input as text.

Verify the latest two stable desktop releases at release time for Chrome, Edge, Firefox, and Safari. Automated Chromium/Firefox/WebKit coverage is supplemented by a real Safari clipboard smoke test. Record the exact tested OS/browser versions rather than treating an engine test as proof for every browser release.

### 11.3 Privacy checks

1. Start a production site in a clean browser context, permit only the initial same-origin asset requests, and wait for worker readiness.
2. Record network activity, disable connectivity, and exercise paste, sample load, toggles, sanitization, Clear, and copying without navigating away. Assert zero new application requests or connection attempts; capture main-page and worker activity.
3. Exercise the same flow with production CSP enforced and check for unexpected policy violations. Confirm no storage, cookie, IndexedDB, or service-worker content is created.
4. Capture console/error events during success/failure tests and assert that input canaries never appear. Review the artifact for analytics and external resource URLs.
5. Run the installed CLI with OS-level network access denied and instrument socket/DNS entry points. Assert no calls are attempted, rather than relying only on the fact that blocked requests failed.
6. Use synthetic fixtures only in traces, screenshots, logs, and CI artifacts. Do not request real leaked credentials in bug reports.

No single passing check proves security against a malicious extension, compromised OS, or arbitrary third-party script; the checks verify the bounded application behavior described here.

### 11.4 Performance verification

On one recorded reference laptop/workstation, after five warm-up runs, measure 30 runs per fixture shape and report p50/p95. Record CPU, RAM, OS, runtime/browser versions, build hash, and rule version. Use no-match, sparse-match, dense-match, Unicode, and long-single-line inputs at the maximum supported size.

| Measure | Release target |
| --- | --- |
| Browser 100 KiB processing | p95 no more than 500 ms from dispatch to rendered result, excluding the 150 ms debounce and initial page load |
| CLI 5 MiB processing | p95 no more than 2 seconds for decode, scan, and encode; report disk I/O and startup separately |
| CLI peak process memory | Engineering budget of 256 MiB for the maximum-size fixtures; profile before changing the design |
| Browser main-thread responsiveness | Typing remains interactive; investigate processing-related long tasks over 50 ms |
| Browser stuck-scan recovery | Timeout state within approximately 2 seconds of dispatch, subject to browser scheduling |

The reference hardware is selected and recorded during implementation. These are acceptance targets, not measured results. Performance failures require optimization or an explicit requirement revision; do not silently drop input, rules, or output.

### 11.5 PRD traceability

| PRD requirement | Technical coverage | Verification |
| --- | --- | --- |
| 7.1 input limits and UTF-8 | Section 5 | Byte-boundary, BOM, invalid-input adapter tests |
| 7.2 and acceptance 1–5 | Sections 6–7 | Rule corpus, overlap and preservation properties |
| 7.3 and acceptance 6 | SR-006 and options contract | Private-range boundaries and option matrix |
| 7.4 CLI contract | Section 8 | Installed-wheel subprocess tests |
| 7.5 playground | Section 9 | Browser user-flow and state tests |
| Acceptance 7 parity | ADR-03 and manifest versioning | Identical corpus results on both runtimes |
| Acceptance 8 offline | Sections 9–10 | Loaded-page offline flow |
| Acceptance 9 copy | Section 9.3 | Current-result, race, and clipboard-denial tests |
| Acceptance 10 warning | Sections 8.2 and 9.1 | stderr/UI warning assertions |
| 10 privacy and security | Section 10 | Network, storage, content-log, artifact checks |
| 10 performance and usability | Sections 9.4 and 11.4 | Benchmarks, contrast and keyboard review |
| 11 pilot outcomes | Approved PRD measurement plan | Opt-in research with synthetic tasks; no embedded analytics |

## 12. Delivery sequence and release requirements

### Milestone 1 — Contract and Python reference

Create the manifest, fixture schema/corpus, Python core, CLI adapter, packaging, and documentation for supported patterns. Establish deterministic output, safe diagnostics, and installed-wheel behavior. Exit when core fixtures and CLI integration checks pass.

### Milestone 2 — Browser implementation and parity

Implement the TypeScript core, worker, controller, landing sections, and clipboard flow. Add generated-manifest verification and cross-runtime fixture comparison. Exit when all shared results match and stale-result/copy tests pass.

### Milestone 3 — Privacy, performance, and compatibility

Build static production assets with the required headers, run offline/network/storage checks, benchmark maximum inputs, and complete keyboard/narrow-screen/browser testing. Fix rule false positives/negatives identified within the supported grammar. Exit when PRD acceptance criteria have recorded evidence.

### Milestone 4 — Release preparation

Prepare an installation guide, supported-rule guide with limitations, changelog, contribution instructions, security-reporting instructions, wheel/source archives, and static site bundle. Record checksums and tested versions. Verify installation from the built artifact with no source checkout available. These are preparation steps; public publication requires a subsequent release action.

CI should run manifest validation, Python tests across supported stable minors on Linux, Windows/macOS adapter coverage, TypeScript type checks/tests, parity, a production build, and browser checks. Dedicated benchmark runs use recorded hardware; variable shared CI timing is a regression signal, not the only performance gate. Freeze dependency locks for release and verify all artifacts derive from one source revision and rule version.

A release must have no unresolved defect that leaks a supported secret into output, copies raw/stale input through the application button, transmits processing content, or produces undocumented cross-runtime differences. Each rule change needs positive, negative, overlap, and regression fixtures. Public claims and version badges must reflect the tested artifact.

For a web regression, restore a previously validated complete static bundle and matching rule version; retain old hashed assets long enough for loaded pages to finish startup. Keep HTML revalidated so new visitors receive the selected version. CLI rollback means explicitly installing a previously validated artifact. Do not add an automatic updater or silently alter rules on users' machines.

## 13. Resolved decisions and remaining ownership

| PRD/review item | Resolution or remaining action | Timing |
| --- | --- | --- |
| Working product name | SpyMonk Redact; renamed from ShareClean on 21 October 2026, before implementation | Resolved |
| Email default | On | Resolved |
| Private IP default and token | Off; `[PRIVATE IP REDACTED]`; RFC1918 IPv4 only | Resolved |
| Python floor and packaging | 3.11+, setuptools build, wheel/source distributions | Resolved for design |
| Cross-runtime consistency | Shared manifest and reviewed fixtures, mirrored scanners | Resolved |
| Character encoding | Strict UTF-8 CLI; explicit Unicode validation and byte limits | Resolved |
| Update checks and telemetry | None | Resolved |
| Extra identifiers and JSON reports | Hostnames/custom rules and public JSON reporting deferred | Resolved |
| Public package/repository identity | Project owner selects and verifies available destinations | Before public release links/install commands |
| License and contribution terms | Project owner selects terms; no license presumed here | Before accepting external contributions or distributing |
| Security contact and triage owner | Project owner names a maintainer and a private reporting route | Before public release |
| Hosting provider and domain | Choose a host that supports the specified headers and no injected analytics | Before deployment |
| Exact dependency versions and reference hardware | Implementer records compatible pinned versions and benchmark machine | During implementation |

Remaining ownership items do not prevent implementing or testing the local design. They are not assumed to have been approved, registered, or configured. No schedule or external maintainer commitment has been invented.

## 14. Design review status

The accompanying [TRD review](TRD_REVIEW-v1.0.md) records the self-review, corrected ambiguities, and implementation risks. The design is ready to guide implementation within the approved product scope. Compliance, performance, rule accuracy, and browser compatibility remain to be demonstrated by the planned tests.
