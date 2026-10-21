# spymonk-redact

Redact passwords, tokens, private keys, cookies, email addresses, and home-directory names from logs, stack traces, and configuration excerpts before you share them. Everything runs locally; nothing is uploaded.

```sh
spymonk-redact app.log > app.redacted.log
kubectl logs pod/api | spymonk-redact --report
python -m spymonk_redact --output clean.log app.log
```

Only matched values change; line breaks, spacing, and encoding are kept byte for byte. Detection is limited to the documented rules, so review the output before sharing and rotate any credential that was already exposed.

- [Rule reference](https://github.com/shubhajeet1207/redact/blob/main/docs/rules.md)
- [Security policy](https://github.com/shubhajeet1207/redact/blob/main/SECURITY.md)
- [Source](https://github.com/shubhajeet1207/redact)

This wheel contains the native `spymonk-redact` binary for your platform. The Python package only provides `python -m spymonk_redact`.
