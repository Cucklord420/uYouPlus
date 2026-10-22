#!/usr/bin/env python3
"""Validate operator-supplied IPA details before privileged build tooling runs."""
import argparse
import hashlib
import ipaddress
import plistlib
import re
import stat
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,4}\Z")
BUNDLE = re.compile(r"[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*){1,8}\Z")
APP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}\Z")
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
MAX_FILES = 100000
MAX_UNPACKED = 8 * 1024**3


def validate_inputs(url: str, digest: str, version: str, bundle: str, app: str) -> None:
    if not SHA256.fullmatch(digest):
        raise ValueError("A 64-character SHA-256 checksum is required for the IPA")
    if not VERSION.fullmatch(version):
        raise ValueError("uYou version must contain only digits and dots")
    if not BUNDLE.fullmatch(bundle):
        raise ValueError("Invalid bundle identifier")
    if not APP_NAME.fullmatch(app) or app.endswith(" "):
        raise ValueError("App display name must use simple printable characters (max 40)")
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError("URL contains spaces or control characters")
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError as e:
        raise ValueError("Invalid IPA URL") from e
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError("IPA URL must use HTTPS without credentials or fragments")
    if port not in (None, 443):
        raise ValueError("Nonstandard HTTPS ports are not allowed")
    host = u.hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP literal URLs are prohibited")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise ValueError("Local network hosts are prohibited")
    if "." not in host or len(host) > 253 or not all(HOST_LABEL.fullmatch(x) for x in host.split(".")):
        raise ValueError("Invalid public DNS hostname")
    if not u.path or u.path.endswith("/"):
        raise ValueError("IPA URL must point to a file")


def verify_ipa(path: Path, expected_sha256: str) -> str:
    if not SHA256.fullmatch(expected_sha256):
        raise ValueError("Invalid SHA-256 digest")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest().lower() != expected_sha256.lower():
        raise ValueError("IPA checksum mismatch; refusing extraction")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("Too many IPA archive entries")
        seen = set()
        total = 0
        for entry in infos:
            name = entry.filename
            segments = name.split("/")
            if (
                not name or name.startswith("/") or "\\" in name or "\0" in name
                or any(part in ("", ".", "..") for part in segments[:-1])
                or ".." in segments or ":" in segments[0]
            ):
                raise ValueError("Unsafe IPA archive entry path")
            file_type = stat.S_IFMT(entry.external_attr >> 16)
            if file_type == stat.S_IFLNK:
                raise ValueError("IPA contains a symbolic link")
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("IPA contains a special file")
            allowed = (
                name in ("Payload/", "Payload/YouTube.app/")
                or name.startswith("Payload/YouTube.app/")
                or (name in ("iTunesMetadata.plist", "iTunesArtwork") and not entry.is_dir())
            )
            if not allowed:
                raise ValueError("IPA contains an unapproved archive member")
            key = name.rstrip("/")
            if key in seen:
                raise ValueError("Duplicate IPA archive entry")
            seen.add(key)
            total += entry.file_size
            if total > MAX_UNPACKED:
                raise ValueError("IPA decompressed size exceeds safety limit")
            if entry.file_size > 64 * 1024 * 1024 and entry.compress_size == 0:
                raise ValueError("Suspicious archive compression ratio")
            if entry.compress_size and entry.file_size > entry.compress_size * 2000:
                raise ValueError("Suspicious archive compression ratio")
        manifest = "Payload/YouTube.app/Info.plist"
        if manifest not in seen:
            raise ValueError("Not a YouTube IPA: missing Info.plist")
        metadata = plistlib.loads(archive.read(manifest))
        version = metadata.get("CFBundleVersion")
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            raise ValueError("Invalid YouTube CFBundleVersion")
        return version


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("inputs")
    for arg in ("url", "sha256", "version", "bundle", "app"):
        p.add_argument("--" + arg, required=True)
    p = commands.add_parser("ipa")
    p.add_argument("--file", required=True, type=Path)
    p.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "inputs":
            validate_inputs(args.url, args.sha256, args.version, args.bundle, args.app)
            print("Operator input validation passed")
        else:
            print(verify_ipa(args.file, args.sha256))
    except (ValueError, OSError, zipfile.BadZipFile, plistlib.InvalidFileException) as exc:
        print("Build input rejected: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
