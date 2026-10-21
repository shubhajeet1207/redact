"""``python -m spymonk_redact [OPTIONS] [FILE | -]``: run the installed binary (TRD §9.9).

The launcher finds the binary maturin installed in the environment's scripts directory (or the
user scripts directory, or next to this package) and runs it with identical arguments. It has no
dependencies and never reads or alters input: on Unix it replaces itself with the binary; on
Windows it waits for the binary and passes its exit code through.
"""

import os
import subprocess
import sys
import sysconfig
from pathlib import Path

_NAME = "spymonk-redact.exe" if os.name == "nt" else "spymonk-redact"


def _binary() -> str:
    candidates = [Path(sysconfig.get_path("scripts")) / _NAME]
    user_scheme = sysconfig.get_preferred_scheme("user")
    candidates.append(Path(sysconfig.get_path("scripts", user_scheme)) / _NAME)
    candidates.append(Path(__file__).resolve().parent / _NAME)
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    sys.stderr.write(
        "spymonk-redact: the spymonk-redact binary is not installed next to this package; "
        "reinstall the spymonk-redact wheel\n"
    )
    sys.exit(1)


def main() -> None:
    exe = _binary()
    args = [exe, *sys.argv[1:]]
    if os.name != "nt":
        os.execv(exe, args)
    child = subprocess.Popen(args)
    while True:
        try:
            sys.exit(child.wait())
        except KeyboardInterrupt:
            # The console delivers Ctrl+C to the binary too; it cleans up and exits with 130.
            continue


if __name__ == "__main__":
    main()
