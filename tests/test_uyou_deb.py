"""Offline, fictional package checks; no network, extraction, or signing."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts.verify_uyou_deb import MAX_PACKAGE_BYTES, verify_package


class PackageIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="uyou-deb-test-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "sample.deb"
        self.content = b"!<arch>\n" + b"synthetic placeholder package for tests"
        self.path.write_bytes(self.content)
        self.sha = hashlib.sha256(self.content).hexdigest()

    def test_valid_synthetic_package(self):
        verify_package(self.sha.upper(), self.path)

    def test_checksum_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            verify_package("0" * 64, self.path)

    def test_missing_invalid_checksum_rejected_before_read(self):
        for checksum in ("", "not-64-hex", "a" * 63, "g" * 64):
            with self.subTest(checksum=checksum), self.assertRaises(ValueError):
                verify_package(checksum, self.path)
        with self.assertRaises(ValueError):
            verify_package("")

    def test_http_error_body_rejected(self):
        self.path.write_bytes(b"HTTP 404 not found")
        with self.assertRaisesRegex(ValueError, "not a Debian ar archive"):
            verify_package(hashlib.sha256(self.path.read_bytes()).hexdigest(), self.path)

    def test_empty_package_rejected(self):
        self.path.write_bytes(b"")
        with self.assertRaises(ValueError):
            verify_package(hashlib.sha256(b"").hexdigest(), self.path)

    def test_symlink_and_directory_rejected(self):
        link = self.path.with_name("package-symlink.deb")
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            verify_package(self.sha, link)
        with self.assertRaises(ValueError):
            verify_package(self.sha, Path(self.tmp.name))

    def test_missing_package_fails_closed(self):
        with self.assertRaises(FileNotFoundError):
            verify_package(self.sha, self.path.with_name("missing.deb"))

    def test_oversized_package_rejected_without_read(self):
        with self.path.open("r+b") as out:
            out.truncate(MAX_PACKAGE_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "512 MiB"):
            verify_package(self.sha, self.path)


    def test_symlinked_package_parent_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="uyou-parent-link-") as tmp:
            root = Path(tmp)
            real_parent = root / "real"
            real_parent.mkdir()
            package = real_parent / "sample.deb"
            package.write_bytes(b"!<arch>\nsynthetic package")
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "parent"):
                verify_package(digest, linked_parent / "sample.deb")


if __name__ == "__main__":
    unittest.main()
