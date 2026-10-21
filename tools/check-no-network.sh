#!/usr/bin/env bash
# TRD §19.7 (Linux): runs the whole fixture corpus through the release binary under strace and
# fails on any network syscall or any process-creation syscall other than strace's own launch of
# the binary. Requires strace.
#
# Usage: tools/check-no-network.sh path/to/spymonk-redact
set -euo pipefail

bin="$(realpath "${1:?usage: check-no-network.sh BINARY}")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

python3 -I tools/fixture-inputs.py "$work/inputs" >/dev/null
count=0
for input in "$work"/inputs/*; do
  # Failures (encoding errors in negative fixtures) are expected; only syscalls matter here.
  strace -f -qq -e trace=%network,%process -o "$work/trace" \
    "$bin" --report-format json --report-file "$work/report.json" "$input" >/dev/null 2>&1 || true
  # Allowed: the initial execve that launches the binary, and process exit.
  unexpected="$(grep -vE "^[0-9]+ +(execve\(\"$bin\"|exit_group\(|\+\+\+ exited)" "$work/trace" || true)"
  if [ -n "$unexpected" ]; then
    echo "check-no-network: unexpected syscalls for $(basename "$input"):" >&2
    printf '%s\n' "$unexpected" >&2
    exit 1
  fi
  count=$((count + 1))
done
echo "check-no-network: $count inputs, zero network or process-creation syscalls"
