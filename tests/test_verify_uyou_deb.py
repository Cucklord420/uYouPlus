"""Synthetic, offline regressions for the uYou package integrity gate."""

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.verify_uyou_deb import main, prepare, valid_sha256, verify_file


class DebIntegrityTests(unittest.TestCase):
    def test_digest_is_required_before_download(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "package.deb"
            with patch("scripts.verify_uyou_deb.subprocess.run") as run:
                self.assertEqual(
                    main(["--file", str(path), "--version", "3.0.3", "--sha256", ""]), 1
                )
                run.assert_not_called()
                self.assertFalse(path.exists())

    def test_cached_package_must_match_independent_digest(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "package.deb"
            approved = b"synthetic package bytes"
            digest = hashlib.sha256(approved).hexdigest()
            path.write_bytes(b"tampered package bytes")
            with patch("scripts.verify_uyou_deb.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "does not match"):
                    prepare(path, "3.0.3", digest)
                run.assert_not_called()
            path.write_bytes(approved)
            self.assertTrue(verify_file(path, digest))
            self.assertFalse(verify_file(path, hashlib.sha256(b"other").hexdigest()))

    def test_download_http_failure_does_not_publish(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "package.deb"
            digest = hashlib.sha256(b"synthetic fixture").hexdigest()
            with patch(
                "scripts.verify_uyou_deb.subprocess.run",
                side_effect=subprocess.CalledProcessError(22, ["curl"]),
            ):
                self.assertEqual(
                    main(["--file", str(path), "--version", "3.0.3", "--sha256", digest]), 1
                )
            self.assertFalse(path.exists())
            self.assertFalse(list(Path(root).glob(".uyou-verified-*")))

    def test_synthetic_download_must_match_before_atomic_publish(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "package.deb"
            approved = b"synthetic vetted package"
            digest = hashlib.sha256(approved).hexdigest()

            def fake_curl(cmd, **kwargs):
                self.assertEqual(
                    cmd[-1],
                    "https://repo.miro92.com/debs/com.miro.uyou_3.0.3_iphoneos-arm.deb",
                )
                self.assertIn("--fail", cmd)
                self.assertEqual(cmd[cmd.index("--proto") + 1], "=https")
                Path(cmd[cmd.index("--output") + 1]).write_bytes(approved)
                return subprocess.CompletedProcess(cmd, 0)

            with patch("scripts.verify_uyou_deb.subprocess.run", side_effect=fake_curl):
                prepare(path, "3.0.3", digest)
            self.assertEqual(path.read_bytes(), approved)
            path.unlink()

            def bad_curl(cmd, **kwargs):
                Path(cmd[cmd.index("--output") + 1]).write_bytes(b"attacker-controlled bytes")
                return subprocess.CompletedProcess(cmd, 0)

            with patch("scripts.verify_uyou_deb.subprocess.run", side_effect=bad_curl):
                with self.assertRaisesRegex(ValueError, "failed SHA-256"):
                    prepare(path, "3.0.3", digest)
            self.assertFalse(path.exists())

    def test_makefile_and_workflow_require_operator_digest(self):
        root = Path(__file__).resolve().parents[1]
        make = (root / "Makefile").read_text()
        workflow = (root / ".github/workflows/buildapp.yml").read_text()
        self.assertLess(
            make.index("scripts/verify_uyou_deb.py"),
            make.index('tar -xf "$(UYOU_DEB)"'),
        )
        self.assertIn("UYOU_DEB_SHA256", make)
        self.assertIn("uyou_deb_sha256:", workflow)
        self.assertIn("UYOU_DEB_SHA256: ${{ inputs.uyou_deb_sha256 }}", workflow)
        self.assertNotIn("curl -s https://repo.miro92.com/debs", make)

    def test_empty_file_and_malformed_version_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "package.deb"
            path.write_bytes(b"")
            expected = "1" * 64
            self.assertFalse(verify_file(path, expected))
            with self.assertRaises(ValueError):
                prepare(path, "3.0.3;evil", expected)
            self.assertFalse(valid_sha256("not-a-digest"))


if __name__ == "__main__":
    unittest.main()
