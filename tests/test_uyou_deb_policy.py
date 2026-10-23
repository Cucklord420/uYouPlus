"""Static regression that binds checksum validation to the manual build path."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BuildChecksumPolicyTests(unittest.TestCase):
    def test_workflow_has_separate_required_deb_digest(self):
        workflow = (ROOT / ".github/workflows/buildapp.yml").read_text()
        self.assertIn("      uyou_deb_sha256:", workflow)
        self.assertIn("          UYOU_DEB_SHA256: ${{ inputs.uyou_deb_sha256 }}", workflow)
        self.assertIn("          UYOU_VERSION: ${{ inputs.uyou_version }}", workflow)
        self.assertIn('python3 scripts/verify_uyou_deb.py --sha256 "$UYOU_DEB_SHA256" --version "$UYOU_VERSION"', workflow)

    def test_makefile_authenticates_before_download_and_extraction(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("export UYOU_VERSION", makefile)
        self.assertLess(makefile.index("verify_uyou_deb.py --sha256"), makefile.index("curl --fail"))
        self.assertLess(
            makefile.index('verify_uyou_deb.py --file "$(UYOU_DEB)" --sha256 "$$UYOU_DEB_SHA256" --version "$$UYOU_VERSION"'),
            makefile.index('extract_uyou_deb.py --file "$(UYOU_DEB)"'),
        )
        self.assertNotIn('dpkg-deb --extract "$(UYOU_DEB)" "$(UYOU_PATH)"', makefile)
        self.assertNotIn('tar -xf "$(UYOU_DEB)"', makefile)
        self.assertIn("--proto-redir '=https'", makefile)
        self.assertIn("--max-filesize 536870912", makefile)


if __name__ == "__main__":
    unittest.main()
