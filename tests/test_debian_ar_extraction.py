"""Offline Debian ar extraction regression: no proprietary uYou bytes are used."""
from pathlib import Path
import hashlib
import os
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
            subprocess.run(
                ["dpkg-deb", "--build", str(source), str(deb)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue(deb.read_bytes().startswith(b"!<arch>\n"))
            dest = root / "extract"
            subprocess.run(
                ["dpkg-deb", "--extract", str(deb), str(dest)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                (dest / "Library/MobileSubstrate/DynamicLibraries/uYou.dylib").read_bytes(),
                b"FICTIONAL DYLIB; NO PROPRIETARY MATERIAL",
            )
            self.assertTrue(
                (dest / "Library/Application Support/uYouBundle.bundle").is_dir()
            )

    def _build_deb(self, root: Path, *, complete: bool) -> Path:
        source = root / "package"
        (source / "DEBIAN").mkdir(parents=True)
        (source / "DEBIAN" / "control").write_text(
            "Package: synthetic-uyou\nVersion: 3.0.3\n"
            "Architecture: iphoneos-arm\nMaintainer: Fixture <fixture@example.invalid>\n"
            "Description: Fictional stale-payload regression\n"
        )
        if complete:
            dylib = source / "Library/MobileSubstrate/DynamicLibraries/uYou.dylib"
            dylib.parent.mkdir(parents=True)
            dylib.write_bytes(b"NEW FICTIONAL DYLIB")
            bundle = source / "Library/Application Support/uYouBundle.bundle"
            bundle.mkdir(parents=True)
            (bundle / "Info.plist").write_text("New synthetic fixture")
        else:
            unrelated = source / "usr/share/doc/synthetic-uyou/readme"
            unrelated.parent.mkdir(parents=True)
            unrelated.write_text("No uYou library payload in this archive.")
        deb = root / "Tweaks/uYou/com.miro.uyou_3.0.3_iphoneos-arm.deb"
        deb.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["dpkg-deb", "--build", str(source), str(deb)],
            check=True,
            capture_output=True,
            text=True,
        )
        return deb

    def _prepare_make_checkout(self, root: Path) -> None:
        shutil.copy2(ROOT / "Makefile", root / "Makefile")
        scripts = root / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "scripts/verify_uyou_deb.py", scripts / "verify_uyou_deb.py")
        makefiles = root / "fake-theos/makefiles"
        makefiles.mkdir(parents=True)
        for name in ("common.mk", "aggregate.mk", "tweak.mk"):
            (makefiles / name).write_text("")

    def _run_make(self, root: Path, digest: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update(
            {
                "THEOS": str(root / "fake-theos"),
                "THEOS_MAKE_PATH": str(root / "fake-theos/makefiles"),
                "UYOU_VERSION": "3.0.3",
                "UYOU_DEB_SHA256": digest,
            }
        )
        return subprocess.run(
            [shutil.which("make") or "make", "-f", "Makefile", "before-all"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    @unittest.skipUnless(
        shutil.which("dpkg-deb") and shutil.which("make"),
        "dpkg-deb and GNU make are required for this integration regression",
    )
    def test_make_rejects_incomplete_package_when_old_payload_exists(self):
        with tempfile.TemporaryDirectory(prefix="uyou-stale-reject-") as tmp:
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            self._prepare_make_checkout(checkout)
            library = checkout / "Tweaks/uYou/Library"
            stale_dylib = library / "MobileSubstrate/DynamicLibraries/uYou.dylib"
            stale_dylib.parent.mkdir(parents=True)
            stale_dylib.write_bytes(b"OLD FICTIONAL DYLIB")
            stale_bundle = library / r"Application\ Support/uYouBundle.bundle"
            stale_bundle.mkdir(parents=True)
            (stale_bundle / "Info.plist").write_text("Stale synthetic bundle")
            deb = self._build_deb(checkout, complete=False)

            result = self._run_make(checkout, hashlib.sha256(deb.read_bytes()).hexdigest())

            self.assertNotEqual(
                result.returncode,
                0,
                "incomplete authenticated archive passed because stale files satisfied the build checks",
            )
            self.assertEqual(stale_dylib.read_bytes(), b"OLD FICTIONAL DYLIB")
            self.assertEqual((stale_bundle / "Info.plist").read_text(), "Stale synthetic bundle")

    @unittest.skipUnless(
        shutil.which("dpkg-deb") and shutil.which("make"),
        "dpkg-deb and GNU make are required for this integration regression",
    )
    def test_make_replaces_old_payload_with_complete_package(self):
        with tempfile.TemporaryDirectory(prefix="uyou-stale-replace-") as tmp:
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            self._prepare_make_checkout(checkout)
            library = checkout / "Tweaks/uYou/Library"
            stale_dylib = library / "MobileSubstrate/DynamicLibraries/uYou.dylib"
            stale_dylib.parent.mkdir(parents=True)
            stale_dylib.write_bytes(b"OLD FICTIONAL DYLIB")
            stale_bundle = library / "Application Support/uYouBundle.bundle"
            stale_bundle.mkdir(parents=True)
            (stale_bundle / "Info.plist").write_text("Old synthetic fixture")
            stale_extra = library / "OldPackageMarker.txt"
            stale_extra.write_text("Must not survive package replacement")
            escaped_stale_bundle = library / r"Application\ Support/uYouBundle.bundle"
            escaped_stale_bundle.mkdir(parents=True)
            deb = self._build_deb(checkout, complete=True)

            result = self._run_make(checkout, hashlib.sha256(deb.read_bytes()).hexdigest())

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                (library / "MobileSubstrate/DynamicLibraries/uYou.dylib").read_bytes(),
                b"NEW FICTIONAL DYLIB",
            )
            self.assertTrue((library / "Application Support/uYouBundle.bundle/Info.plist").is_file())
            self.assertFalse(stale_extra.exists())
            self.assertFalse(escaped_stale_bundle.exists())


if __name__ == "__main__":
    unittest.main()
