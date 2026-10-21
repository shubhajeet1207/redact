"""Writes every fixture input, and the benign corpus, to a directory, one file per case.

Used by the network-absence check (TRD §19.7) and fuzz seeding. Input only; no options.
Usage: python3 -I tools/fixture-inputs.py OUT_DIR
"""

import base64
import glob
import json
import os
import sys


def main() -> None:
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    n = 0
    for path in sorted(glob.glob("fixtures/**/*.json", recursive=True)):
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        for fx in doc.get("fixtures", []):
            if "inputBase64" in fx:
                data = base64.b64decode(fx["inputBase64"])
            else:
                data = fx.get("input", "").encode("utf-8")
            with open(os.path.join(out, f"case-{n:04d}"), "wb") as f:
                f.write(data)
            n += 1
    for path in sorted(glob.glob("fixtures/benign/*.log")):
        with open(path, "rb") as src, open(os.path.join(out, f"case-{n:04d}"), "wb") as dst:
            dst.write(src.read())
        n += 1
    print(f"{n} inputs written to {out}")


if __name__ == "__main__":
    main()
