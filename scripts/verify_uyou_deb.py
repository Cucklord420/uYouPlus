#!/usr/bin/env python3
"""Fail-closed offline check for the externally sourced uYou Debian package."""
import argparse
import hashlib
import re
import stat
import sys
from pathlib import Path
from typing import Optional

MAX_PACKAGE_BYTES = 512 * 1024 * 1024
HASH = re.compile(r"[0-9a-fA-F]{64}\Z")
VERSION = re.compile(r"[0-9][A-Za-z0-9._+-]{0,39}\Z")
AR_MAGIC = b"!<arch>\n"


def verify_package(
    expected_sha256: str, path: Optional[Path] = None, version: Optional[str] = None
) -> None:
    if HASH.fullmatch(expected_sha256) is None:
        raise ValueError("A reviewed 64-character uYou package SHA-256 is required")
    if version is not None and VERSION.fullmatch(version) is None:
        raise ValueError("uYou package version is invalid")
    if path is None:
        return
    path = Path(path)
    if path.parent.is_symlink():
        raise ValueError("uYou package parent path must not be a symlink")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size < len(AR_MAGIC):
        raise ValueError("uYou package must be a nonempty regular Debian archive")
    if info.st_size > MAX_PACKAGE_BYTES:
        raise ValueError("uYou package exceeds the 512 MiB size limit")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        if stream.read(len(AR_MAGIC)) != AR_MAGIC:
            raise ValueError("uYou download is not a Debian ar archive")
        stream.seek(0)
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_PACKAGE_BYTES:
                raise ValueError("uYou package exceeds the 512 MiB size limit")
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256.lower():
        raise ValueError("uYou package SHA-256 mismatch; refusing extraction")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    try:
        verify_package(args.sha256, args.file, args.version)
    except (ValueError, OSError) as exc:
        print("uYou package rejected: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None
    print("uYou package checksum policy accepted" if args.file is None else "uYou package integrity verified")


if __name__ == "__main__":
    main()
