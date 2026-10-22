#!/usr/bin/env python3
"""Fail-closed byte validation for the independently reviewed uYou package."""
import argparse
import hashlib
import hmac
import os
import re
import stat
import sys
from pathlib import Path

DIGEST = re.compile(r"[0-9a-fA-F]{64}\Z")
AR_MAGIC = b"!<arch>\n"


def verify_package(path: Path, expected_sha256: str) -> None:
    if not DIGEST.fullmatch(expected_sha256):
        raise ValueError("an independently verified 64-hex SHA-256 is required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= len(AR_MAGIC):
            raise ValueError("uYou download is not a nonempty regular Debian archive")
        if stream.read(len(AR_MAGIC)) != AR_MAGIC:
            raise ValueError("uYou download is not a Debian ar archive")
        stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256.lower()):
        raise ValueError("uYou Debian package SHA-256 mismatch; refusing extraction")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        verify_package(args.file, args.sha256)
    except (ValueError, OSError) as exc:
        print(f"uYou package rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
