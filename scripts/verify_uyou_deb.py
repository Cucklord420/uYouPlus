#!/usr/bin/env python3
"""Verify the independently approved uYou package digest before extraction."""

import argparse
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MAX_BYTES = 256 * 1024 * 1024


def valid_sha256(value: str) -> bool:
    return re.fullmatch(r"[a-fA-F0-9]{64}", value) is not None


def verify_file(path: Path, expected: str) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return hmac.compare_digest(digest.hexdigest(), expected.lower())


def prepare(path: Path, version: str, expected: str) -> None:
    if not valid_sha256(expected):
        raise ValueError("an independently reviewed 64-hex SHA-256 is required")
    if not re.fullmatch(r"[0-9][A-Za-z0-9._+-]{0,39}", version):
        raise ValueError("uYou package version is invalid")
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("uYou package path must not be a symlink")
    if path.exists():
        if not verify_file(path, expected):
            raise ValueError("cached uYou package does not match the reviewed SHA-256")
        return
    if not path.parent.is_dir():
        raise ValueError("uYou package directory is missing")

    url = f"https://repo.miro92.com/debs/com.miro.uyou_{version}_iphoneos-arm.deb"
    fd, temp_name = tempfile.mkstemp(prefix=".uyou-verified-", dir=path.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        subprocess.run(
            [
                "curl", "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https",
                "--max-redirs", "3", "--retry", "2", "--connect-timeout", "20",
                "--max-time", "300", "--max-filesize", str(MAX_BYTES),
                "--output", str(temp_path), url,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if not verify_file(temp_path, expected):
            raise ValueError("downloaded uYou package failed SHA-256 or size validation")
        if path.exists() or path.is_symlink():
            raise ValueError("uYou package appeared during download; refusing replacement")
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--file", type=Path)
    parser.add_argument("--version")
    args = parser.parse_args(argv)
    try:
        if not valid_sha256(args.sha256):
            raise ValueError("an independently reviewed 64-hex SHA-256 is required")
        if not args.check_only:
            if args.file is None or args.version is None:
                parser.error("--file and --version are required unless --check-only is used")
            prepare(args.file, args.version, args.sha256)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        # Do not echo package bytes or provider response bodies into CI logs.
        print(f"uYou package verification failed: {error if isinstance(error, ValueError) else 'I/O or download error'}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
