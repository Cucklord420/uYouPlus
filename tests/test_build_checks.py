"""Offline tests: only generated fake ZIP members and fake checksums."""
import hashlib
import plistlib
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from scripts.build_checks import validate_inputs, verify_ipa

URL = "https://downloads.example.org/my.ipa"
SHA = "f" * 64
VER = "3.0.3"
BUNDLE = "com.google.ios.youtube"
APP = "YouTube"


class InputTests(unittest.TestCase):
    def check(self, **kwargs):
        values = dict(url=URL, digest=SHA, version=VER, bundle=BUNDLE, app=APP)
        values.update(kwargs)
        return validate_inputs(**values)

    def test_01_normal(self): self.check()
    def test_02_signed_query(self): self.check(url=URL + "?token=abc&expires=123")
    def test_03_http_rejected(self):
        with self.assertRaises(ValueError): self.check(url=URL.replace("https:", "http:"))
    def test_04_url_credentials_rejected(self):
        with self.assertRaises(ValueError): self.check(url="https://user:pw@downloads.example.org/my.ipa")
    def test_05_localhost_rejected(self):
        with self.assertRaises(ValueError): self.check(url="https://localhost/my.ipa")
    def test_06_local_ip_rejected(self):
        with self.assertRaises(ValueError): self.check(url="https://127.0.0.1/my.ipa")
    def test_07_internal_host_rejected(self):
        with self.assertRaises(ValueError): self.check(url="https://host.internal/my.ipa")
    def test_08_nonstandard_port_rejected(self):
        with self.assertRaises(ValueError): self.check(url="https://downloads.example.org:8443/my.ipa")
    def test_09_fragment_rejected(self):
        with self.assertRaises(ValueError): self.check(url=URL + "#archive")
    def test_10_shell_newline_rejected(self):
        with self.assertRaises(ValueError): self.check(url=URL + "\ncommand")
    def test_11_version_injection_rejected(self):
        with self.assertRaises(ValueError): self.check(version="3.0.3; touch /tmp/pwn")
    def test_12_bundle_injection_rejected(self):
        with self.assertRaises(ValueError): self.check(bundle="com.example.youtube#evil")
    def test_13_app_name_injection_rejected(self):
        with self.assertRaises(ValueError): self.check(app="YouTube$(touch abc)")
    def test_14_missing_hash_rejected(self):
        with self.assertRaises(ValueError): self.check(digest="")
    def test_15_valid_custom_name(self): self.check(app="YouTube Test-1")


class IPATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ipa-checks-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fake.ipa"

    def write_ipa(self, *, entries=(), version="19.25.4"):
        plist = plistlib.dumps(dict(CFBundleVersion=version))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.path, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("Payload/YouTube.app/Info.plist", plist)
                for entry in entries:
                    if len(entry) == 3:
                        name, body, attrs = entry
                        zi = zipfile.ZipInfo(name)
                        zi.create_system = 3
                        zi.external_attr = attrs << 16
                        z.writestr(zi, body)
                    else:
                        name, body = entry
                        z.writestr(name, body)
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_16_fake_valid_ipa(self):
        digest = self.write_ipa()
        self.assertEqual(verify_ipa(self.path, digest), "19.25.4")

    def test_17_checksum_mismatch(self):
        self.write_ipa()
        with self.assertRaises(ValueError): verify_ipa(self.path, SHA)

    def test_18_path_traversal_rejected(self):
        digest = self.write_ipa(entries=[("../escape", b"evil")])
        with self.assertRaises(ValueError): verify_ipa(self.path, digest)

    def test_19_nested_traversal_rejected(self):
        digest = self.write_ipa(entries=[("Payload/../escape", b"evil")])
        with self.assertRaises(ValueError): verify_ipa(self.path, digest)

    def test_20_windows_backslash_rejected(self):
        digest = self.write_ipa(entries=[("Payload\\escape", b"evil")])
        with self.assertRaises(ValueError): verify_ipa(self.path, digest)

    def test_21_symlink_rejected(self):
        digest = self.write_ipa(entries=[("Payload/YouTube.app/link", b"../../bad", stat.S_IFLNK | 0o777)])
        with self.assertRaises(ValueError): verify_ipa(self.path, digest)

    def test_22_duplicate_entry_rejected(self):
        digest = self.write_ipa(entries=[("Payload/YouTube.app/Info.plist", b"duplicate")])
        with self.assertRaises(ValueError): verify_ipa(self.path, digest)

    def test_23_bad_app_version_rejected(self):
        digest = self.write_ipa(version="$(bad)")
        with self.assertRaises(ValueError): verify_ipa(self.path, digest)

    def test_24_invalid_zip_rejected(self):
        self.path.write_bytes(b"not an IPA")
        with self.assertRaises(zipfile.BadZipFile):
            verify_ipa(self.path, hashlib.sha256(self.path.read_bytes()).hexdigest())


    def test_25_rejects_unexpected_archive_roots(self):
        for name in ("unapproved.txt", "Makefile", ".github/workflows/unsafe.yml",
                     "Payload/Other.app/Info.plist"):
            with self.subTest(name=name):
                digest = self.write_ipa(entries=[(name, b"synthetic fixture")])
                with self.assertRaisesRegex(ValueError, "Unexpected IPA archive entry"):
                    verify_ipa(self.path, digest)

    def test_26_rejects_unsupported_archive_file_types(self):
        digest = self.write_ipa(entries=[("Payload/YouTube.app/pipe", b"x", stat.S_IFIFO | 0o644)])
        with self.assertRaisesRegex(ValueError, "Unsupported IPA archive entry type"):
            verify_ipa(self.path, digest)

    def test_27_accepts_expected_app_and_optional_metadata(self):
        digest = self.write_ipa(entries=[
            ("Payload/YouTube.app/Resource.txt", b"synthetic"),
            ("iTunesArtwork", b"synthetic"),
            ("iTunesMetadata.plist", b"synthetic"),
        ])
        self.assertEqual(verify_ipa(self.path, digest), "19.25.4")


if __name__ == "__main__":
    unittest.main()
