"""Offline regression tests for the fail-closed uYou package verifier."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch-verified-uyou-deb.sh"
PAYLOAD = b"!<arch>\nFICTIONAL TEST DEB; NOT A REAL PACKAGE\n"


class VerifiedUyouDebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="uyou-verifier-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.destination = self.root / "uYou" / "com.miro.uyou_3.0.3_iphoneos-arm.deb"
        self.digest = hashlib.sha256(PAYLOAD).hexdigest()
        self.fakebin = self.root / "fakebin"
        self.fakebin.mkdir()
        self.source = self.root / "fictional-source"
        self.source.write_bytes(PAYLOAD)
        self.marker = self.root / "curl-invoked"
        stub = self.fakebin / "curl"
        stub.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys,pathlib\n"
            "args=sys.argv[1:]\n"
            "pathlib.Path(os.environ['CURL_MARKER']).write_text('called')\n"
            "assert all(flag in args for flag in ['--fail','--location','--proto','--proto-redir','--max-redirs','--max-time'])\n"
            "assert args[-1].startswith('https://repo.miro92.com/debs/')\n"
            "if os.environ.get('CURL_SHOULD_FAIL')=='1': sys.exit(22)\n"
            "out=pathlib.Path(args[args.index('--output')+1])\n"
            "out.write_bytes(pathlib.Path(os.environ['CURL_SOURCE']).read_bytes())\n"
        )
        stub.chmod(0o755)

    def call_verifier(self, expected=None, version="3.0.3", fail_download=False):
        env = os.environ.copy()
        env["PATH"] = str(self.fakebin) + os.pathsep + env.get("PATH", "")
        env["CURL_MARKER"] = str(self.marker)
        env["CURL_SOURCE"] = str(self.source)
        env["CURL_SHOULD_FAIL"] = "1" if fail_download else "0"
        return subprocess.run(
            ["bash", str(SCRIPT), version, str(self.destination), expected if expected is not None else ""],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    def test_missing_digest_blocks_before_download(self):
        result = self.call_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.destination.exists())

    def test_https_download_and_verified_publish(self):
        result = self.call_verifier(expected=self.digest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.read_bytes(), PAYLOAD)
        self.assertTrue(self.marker.exists())

    def test_tampered_download_refused_and_temp_cleaned(self):
        self.source.write_bytes(b"FAKE TAMPERED PACKAGE")
        result = self.call_verifier(expected=self.digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.destination.parent.glob("*.part.*")), [])
        self.assertNotIn("FAKE TAMPERED PACKAGE", result.stderr)

    def test_http_error_refused_without_cached_package(self):
        result = self.call_verifier(expected=self.digest, fail_download=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.destination.parent.glob("*.part.*")), [])

    def test_existing_cache_is_always_reverified(self):
        self.destination.parent.mkdir(parents=True)
        self.destination.write_bytes(PAYLOAD)
        result = self.call_verifier(expected=self.digest, fail_download=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())
        self.destination.write_bytes(b"CHANGED")
        result = self.call_verifier(expected=self.digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.destination.read_bytes(), b"CHANGED")

    def test_symlink_and_invalid_version_refused(self):
        target = self.root / "outside"
        target.write_bytes(PAYLOAD)
        self.destination.parent.mkdir(parents=True)
        try:
            self.destination.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unsupported")
        result = self.call_verifier(expected=self.digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), PAYLOAD)
        self.assertFalse(self.marker.exists())
        self.destination.unlink()
        result = self.call_verifier(expected=self.digest, version="3.0.3;touch BAD")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_makefile_keeps_hash_gate_before_extraction(self):
        makefile = (SCRIPT.parent.parent / "Makefile").read_text()
        self.assertIn('bash scripts/fetch-verified-uyou-deb.sh', makefile)
        self.assertIn("dpkg-deb --extract", makefile)
        self.assertLess(makefile.index("bash scripts/fetch-verified-uyou-deb.sh"),
                        makefile.index("dpkg-deb --extract"))
        self.assertNotIn("curl -s https://repo.miro92.com", makefile)


if __name__ == "__main__":
    unittest.main()
