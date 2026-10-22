"""Offline Debian ar extraction regression: no proprietary uYou bytes are used."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DebianArExtractionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is not installed")
    def test_synthetic_debian_archive_extracts_expected_bundle(self):
        with tempfile.TemporaryDirectory(prefix="uyou-debian-ar-") as tmp:
            root = Path(tmp)
            source = root / "source"
            (source / "DEBIAN").mkdir(parents=True)
            (source / "DEBIAN" / "control").write_text(
                "Package: synthetic-uyou\nVersion: 3.0.3\n"
                "Architecture: iphoneos-arm\nMaintainer: Fixture <fixture@example.invalid>\n"
                "Description: Fictional Debian archive to test extraction\n"
            )
            dylib = source / "Library/MobileSubstrate/DynamicLibraries/uYou.dylib"
            dylib.parent.mkdir(parents=True)
            dylib.write_bytes(b"FICTIONAL DYLIB; NO PROPRIETARY MATERIAL")
            bundle = source / "Library/Application Support/uYouBundle.bundle"
            bundle.mkdir(parents=True)
            (bundle / "Info.plist").write_text("Synthetic fixture")
            deb = root / "synthetic.deb"
            subprocess.run(["dpkg-deb", "--build", str(source), str(deb)],
                           check=True, capture_output=True, text=True)
            self.assertTrue(deb.read_bytes().startswith(b"!<arch>\n"))
            dest = root / "extract"
            subprocess.run(["dpkg-deb", "--extract", str(deb), str(dest)],
                           check=True, capture_output=True, text=True)
            self.assertEqual(
                (dest / "Library/MobileSubstrate/DynamicLibraries/uYou.dylib").read_bytes(),
                b"FICTIONAL DYLIB; NO PROPRIETARY MATERIAL"
            )
            self.assertTrue((dest / "Library/Application Support/uYouBundle.bundle").is_dir())

    def test_makefile_extracts_verified_deb_as_ar_not_tar(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn('python3 scripts/verify_uyou_deb.py --file "$(UYOU_DEB)"', makefile)
        self.assertIn('dpkg-deb --extract "$(UYOU_DEB)" "$(UYOU_PATH)"', makefile)
        self.assertLess(makefile.index('python3 scripts/verify_uyou_deb.py --file "$(UYOU_DEB)"'),
                        makefile.index('dpkg-deb --extract "$(UYOU_DEB)"'))
        self.assertNotIn('tar -xf "$(UYOU_DEB)"', makefile)


if __name__ == "__main__":
    unittest.main()
