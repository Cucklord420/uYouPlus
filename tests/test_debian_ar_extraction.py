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

    def _build_deb(self, root: Path, *, complete: bool, version: str = "3.0.3", output=None) -> Path:
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
        deb = output or root / f"Tweaks/uYou/com.miro.uyou_{version}_iphoneos-arm.deb"
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
        shutil.copy2(ROOT / "scripts/extract_uyou_deb.py", scripts / "extract_uyou_deb.py")
        makefiles = root / "fake-theos/makefiles"
        makefiles.mkdir(parents=True)
        for name in ("common.mk", "aggregate.mk", "tweak.mk"):
            (makefiles / name).write_text("")

    def _run_make(self, root: Path, digest: str, version: str = "3.0.3", path_prefix=None, extra_env=None) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        if path_prefix is not None:
            env["PATH"] = str(path_prefix) + os.pathsep + env.get("PATH", "")
        if extra_env:
            env.update(extra_env)
        env.update(
            {
                "THEOS": str(root / "fake-theos"),
                "THEOS_MAKE_PATH": str(root / "fake-theos/makefiles"),
                "UYOU_VERSION": version,
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


    def _write_fake_curl(self, bin_dir: Path) -> None:
        bin_dir.mkdir(parents=True)
        curl = bin_dir / "curl"
        curl.write_text(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "import shutil\n"
            "import sys\n"
            "args = sys.argv[1:]\n"
            "output = Path(args[args.index('--output') + 1])\n"
            "if os.environ.get('SYNTHETIC_CURL_FAIL') == '1':\n"
            "    output.write_bytes(b'HTTP 503 synthetic failure')\n"
            "    raise SystemExit(22)\n"
            "shutil.copyfile(os.environ['SYNTHETIC_DEB'], output)\n"
        )
        curl.chmod(0o755)

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


    @unittest.skipUnless(
        shutil.which("dpkg-deb") and shutil.which("make"),
        "dpkg-deb and GNU make are required for this integration regression",
    )
    def test_make_rejects_malformed_version_before_reusing_cached_package(self):
        with tempfile.TemporaryDirectory(prefix="uyou-invalid-version-") as tmp:
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            self._prepare_make_checkout(checkout)
            version = "3.0.3;malformed"
            self._build_deb(checkout, complete=True, version=version)

            result = self._run_make(
                checkout,
                hashlib.sha256(
                    (checkout / "Tweaks/uYou" / f"com.miro.uyou_{version}_iphoneos-arm.deb").read_bytes()
                ).hexdigest(),
                version=version,
            )

            self.assertNotEqual(
                result.returncode,
                0,
                "a malformed package version reached cached package extraction",
            )
            self.assertFalse((checkout / "Tweaks/uYou/Library").exists())


    @unittest.skipUnless(
        shutil.which("dpkg-deb") and shutil.which("make"),
        "dpkg-deb and GNU make are required for this integration regression",
    )
    def test_failed_download_does_not_publish_or_leave_temporary_package(self):
        with tempfile.TemporaryDirectory(prefix="uyou-download-failure-") as tmp:
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            self._prepare_make_checkout(checkout)
            fake_bin = Path(tmp) / "fake-bin"
            self._write_fake_curl(fake_bin)

            result = self._run_make(
                checkout,
                "a" * 64,
                path_prefix=fake_bin,
                extra_env={"SYNTHETIC_CURL_FAIL": "1"},
            )

            package = checkout / "Tweaks/uYou/com.miro.uyou_3.0.3_iphoneos-arm.deb"
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(package.exists())
            self.assertEqual(list(package.parent.glob("*.download.*")), [])

    @unittest.skipUnless(
        shutil.which("dpkg-deb") and shutil.which("make"),
        "dpkg-deb and GNU make are required for this integration regression",
    )
    def test_downloaded_package_is_verified_then_promoted_and_extracted(self):
        with tempfile.TemporaryDirectory(prefix="uyou-download-success-") as tmp:
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            self._prepare_make_checkout(checkout)
            fixture_deb = self._build_deb(
                checkout,
                complete=True,
                output=checkout / "synthetic-source.deb",
            )
            fake_bin = Path(tmp) / "fake-bin"
            self._write_fake_curl(fake_bin)

            result = self._run_make(
                checkout,
                hashlib.sha256(fixture_deb.read_bytes()).hexdigest(),
                path_prefix=fake_bin,
                extra_env={"SYNTHETIC_DEB": str(fixture_deb)},
            )

            package = checkout / "Tweaks/uYou/com.miro.uyou_3.0.3_iphoneos-arm.deb"
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(package.read_bytes(), fixture_deb.read_bytes())
            self.assertEqual(
                (checkout / "Tweaks/uYou/Library/MobileSubstrate/DynamicLibraries/uYou.dylib").read_bytes(),
                b"NEW FICTIONAL DYLIB",
            )
            self.assertEqual(list(package.parent.glob("*.download.*")), [])


if __name__ == "__main__":
    unittest.main()
