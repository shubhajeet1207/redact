"""Reproducible release archives (TRD §14.2, §14.4).

Entries are sorted, timestamps come from SOURCE_DATE_EPOCH, owners are 0, modes are fixed
(0755 for executables, 0644 otherwise), and gzip carries no file name or time. The same inputs
therefore give byte-identical archives on every runner.

Usage:
  python3 -I tools/package-archive.py binary  OUT.tar.gz|OUT.zip  BINARY  [EXTRA_FILE...]
  python3 -I tools/package-archive.py web     OUT.tar.gz  DIST_DIR
The archive's top-level directory is OUT's name without its extension. For `web`, a
build-manifest.json listing every file's SHA-256 is added to the bundle.
"""

import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import time
import zipfile

EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))


def stem(path: str) -> str:
    name = os.path.basename(path)
    for ext in (".tar.gz", ".zip"):
        if name.endswith(ext):
            return name[: -len(ext)]
    raise SystemExit(f"package-archive: unsupported archive name {name}")


def write_tar_gz(out: str, entries: list[tuple[str, bytes, int]]) -> None:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data, mode in sorted(entries):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = EPOCH
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    with open(out, "wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=EPOCH, compresslevel=9) as gz:
        gz.write(raw.getvalue())


def write_zip(out: str, entries: list[tuple[str, bytes, int]]) -> None:
    # ZIP timestamps cannot precede 1980.
    stamp = max(EPOCH, 315532800)
    when = tuple(time.gmtime(stamp)[:6])
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data, mode in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=when)
            info.external_attr = (0o100000 | mode) << 16
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def binary(out: str, binary_path: str, extras: list[str]) -> None:
    top = stem(out)
    entries = [(f"{top}/{os.path.basename(binary_path)}", read(binary_path), 0o755)]
    for extra in extras:
        entries.append((f"{top}/{os.path.basename(extra)}", read(extra), 0o644))
    (write_zip if out.endswith(".zip") else write_tar_gz)(out, entries)


def web(out: str, dist: str) -> None:
    top = stem(out)
    files = []
    for root, _dirs, names in os.walk(dist):
        for name in names:
            full = os.path.join(root, name)
            files.append((os.path.relpath(full, dist).replace(os.sep, "/"), read(full)))
    files.sort()
    manifest = {
        "name": top,
        "files": [{"path": p, "sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d)} for p, d in files],
    }
    entries = [(f"{top}/{p}", d, 0o644) for p, d in files]
    entries.append((f"{top}/build-manifest.json", (json.dumps(manifest, indent=2) + "\n").encode(), 0o644))
    write_tar_gz(out, entries)


def main() -> None:
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    kind, out = sys.argv[1], sys.argv[2]
    if kind == "binary":
        binary(out, sys.argv[3], sys.argv[4:])
    elif kind == "web":
        web(out, sys.argv[3])
    else:
        raise SystemExit(__doc__)
    print(f"{out} {hashlib.sha256(read(out)).hexdigest()}")


if __name__ == "__main__":
    main()
