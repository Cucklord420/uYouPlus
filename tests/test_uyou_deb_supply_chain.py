"""Offline regression for authenticated uYou .deb retrieval (no network or extraction)."""
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FETCH = ROOT / "scripts" / "fetch_uyou_deb.sh"
PAYLOAD = b"!<arch>\n" + b"synthetic test archive, no executable code"
GOOD_SHA = hashlib.sha256(PAYLOAD).hexdigest()


class PackageSupplyChainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.package = self.root / "uyou.deb"

    def fake_curl(self, code=0, payload=PAYLOAD):
        stub = self.bin / "curl"
        stub.write_text(
            "#!/bin/sh\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = --output ]; then shift; output=$1; fi\n"
            "  shift\n"
            "done\n"
            f"printf '%s' '{payload.decode()}' > \"$output\"\n"
            f"exit {code}\n"
        )
        stub.chmod(0o755)

    def run_fetch(self, digest=GOOD_SHA, version="3.0.3"):
        env = os.environ.copy()
        env.update(UYOU_VERSION=version, UYOU_DEB_SHA256=digest,
                   PATH=str(self.bin) + os.pathsep + env.get("PATH", ""))
        return subprocess.run(["sh", str(FETCH), str(self.package)],
                              env=env, text=True, capture_output=True)

    def test_valid_cached_archive(self):
        self.package.write_bytes(PAYLOAD)
        self.assertEqual(self.run_fetch().returncode, 0)
        self.assertEqual(self.package.read_bytes(), PAYLOAD)

    def test_tampered_cached_archive_is_rejected(self):
        self.package.write_bytes(PAYLOAD + b"tampered")
        self.assertNotEqual(self.run_fetch().returncode, 0)
        self.assertEqual(self.package.read_bytes(), PAYLOAD + b"tampered")

    def test_bad_digest_and_version_fail_before_network(self):
        for digest, version in (("", "3.0.3"), ("z" * 64, "3.0.3"), (GOOD_SHA, "3.0;evil")):
            with self.subTest(digest=digest, version=version):
                self.assertNotEqual(self.run_fetch(digest, version).returncode, 0)
                self.assertFalse(self.package.exists())

    def test_http_failure_cannot_publish_partial_download(self):
        self.fake_curl(code=22)
        self.assertNotEqual(self.run_fetch().returncode, 0)
        self.assertFalse(self.package.exists())
        self.assertFalse(list(self.root.glob("*.part.*")))

    def test_verified_download_is_published(self):
        self.fake_curl()
        self.assertEqual(self.run_fetch().returncode, 0)
        self.assertEqual(self.package.read_bytes(), PAYLOAD)
        self.assertFalse(list(self.root.glob("*.part.*")))

    def test_download_digest_mismatch_cannot_publish(self):
        self.fake_curl(payload=PAYLOAD + b"changed")
        self.assertNotEqual(self.run_fetch().returncode, 0)
        self.assertFalse(self.package.exists())
        self.assertFalse(list(self.root.glob("*.part.*")))

    def test_symlinked_cached_archive_is_rejected(self):
        original = self.root / "original.deb"
        original.write_bytes(PAYLOAD)
        self.package.symlink_to(original)
        self.assertNotEqual(self.run_fetch().returncode, 0)
        self.assertEqual(original.read_bytes(), PAYLOAD)

    def test_wrong_archive_magic_is_rejected(self):
        self.package.write_bytes(b"not-a-deb" + PAYLOAD)
        checksum = hashlib.sha256(self.package.read_bytes()).hexdigest()
        self.assertNotEqual(self.run_fetch(checksum).returncode, 0)


if __name__ == "__main__":
    unittest.main()
