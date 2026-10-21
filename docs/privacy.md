# Privacy notice

This notice covers the SpyMonk Redact website and command-line tool (TRD §18).

## Your content

- Text you paste and files you choose are processed **on your device**: in your browser tab, or by the command-line tool on your machine. They are never sent to the project, the website host, or anyone else.
- The website's security policy forbids network connections from the page and from its engine, and the command-line tool contains no networking code.
- Leaving the page clears the editor, the output, and the engine. JavaScript strings cannot be wiped from memory; they are released for garbage collection.

## What the website stores

Nothing. It uses no cookies, local storage, session storage, IndexedDB, Cache API, or service worker, and no analytics, advertising, fonts, or other third-party resources. Your input never appears in a URL.

## What the host records

Like any website, the host that serves the pages records ordinary request metadata in its access logs: your IP address, browser user agent, the page requested, and the time. Retention is set to the host's minimum, targeted at 7 days or less, and IP truncation is enabled where the host supports it. The project never receives these logs for any purpose other than operating the site.

## Trust in the delivered code

Each visit trusts the host to deliver unmodified code. Assets are protected by Subresource Integrity, and every release will publish a build manifest with the SHA-256 of each file. For sensitive material, use the command-line tool or a verified offline copy of the site.

## Downloads

When you save a sanitized file, your browser records the file name in its download history. The tool does not control that record.

## Contact

Report privacy or security concerns through the repository's [private vulnerability reporting](https://github.com/shubhajeet1207/redact/security/advisories/new). See [SECURITY.md](../SECURITY.md).
