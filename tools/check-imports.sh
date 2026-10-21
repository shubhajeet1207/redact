#!/usr/bin/env bash
# TRD §9.8 release check: fails if a release binary imports any socket, DNS, HTTP, or
# process-creation API. Uses LLVM's object tools from the pinned toolchain (`rustup component add
# llvm-tools`), so ELF, Mach-O, and PE are read the same way on every runner.
#
# Usage: tools/check-imports.sh path/to/spymonk-redact[.exe]
set -euo pipefail

bin="${1:?usage: check-imports.sh BINARY}"
sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | sed -n 's/^host: //p')"
tools="$sysroot/lib/rustlib/$host/bin"
ext=""
case "$host" in *windows*) ext=".exe" ;; esac

# Symbols that would mean networking or process creation is reachable from the binary.
banned='^(_?(socket|socketpair|connect|bind|listen|accept|accept4|sendto|sendmsg|sendmmsg|recvfrom|recvmsg|getaddrinfo|gethostbyname|gethostbyname2|getnameinfo|execve|execv|execvp|execvpe|execveat|fork|vfork|posix_spawn|posix_spawnp|system|popen|ptrace)|WSAStartup|WSASocketW|WSAConnect|GetAddrInfoW|getaddrinfo|CreateProcessW|CreateProcessA|CreateProcessAsUserW|ShellExecuteW|WinHttpOpen|InternetOpenW|URLDownloadToFileW)$'
banned_dlls='^(ws2_32|wsock32|winhttp|wininet|urlmon|mswsock|dnsapi|iphlpapi)\.dll$'

case "$(head -c 4 "$bin" | od -An -tx1 | tr -d ' ')" in
  7f454c46*) format=elf ;;
  4d5a*) format=pe ;;
  cffaedfe* | cefaedfe* | cafebabe*) format=macho ;;
  *) echo "check-imports: unknown binary format: $bin" >&2; exit 2 ;;
esac

if [ "$format" = pe ]; then
  imports="$("$tools/llvm-readobj$ext" --coff-imports "$bin")"
  dlls="$(printf '%s\n' "$imports" | sed -n 's/^ *Name: //p' | tr 'A-Z' 'a-z' | sort -u)"
  symbols="$(printf '%s\n' "$imports" | sed -n 's/^ *Symbol: \([^ ]*\).*/\1/p' | sort -u)"
  bad_dlls="$(printf '%s\n' "$dlls" | grep -E "$banned_dlls" || true)"
  if [ -n "$bad_dlls" ]; then
    echo "check-imports: networking DLLs imported:" >&2
    printf '  %s\n' $bad_dlls >&2
    exit 1
  fi
else
  # Undefined (imported) symbols for dynamic binaries; every symbol for static ones.
  symbols="$("$tools/llvm-nm$ext" --undefined-only --just-symbol-name "$bin" 2>/dev/null || true)"
  if [ -z "$symbols" ]; then
    symbols="$("$tools/llvm-nm$ext" --just-symbol-name "$bin" 2>/dev/null || true)"
  fi
  symbols="$(printf '%s\n' "$symbols" | sed 's/@.*//' | sort -u)"
fi

bad="$(printf '%s\n' "$symbols" | grep -E "$banned" || true)"
if [ -n "$bad" ]; then
  echo "check-imports: banned symbols referenced by $bin:" >&2
  printf '  %s\n' $bad >&2
  exit 1
fi
echo "check-imports: $format binary has no networking or process-creation imports"
