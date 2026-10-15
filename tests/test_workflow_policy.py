"""Policy checks for the manual IPA builder, independent of a real proprietary IPA."""
from pathlib import Path
import re
import unittest

WORKFLOW = (Path(__file__).resolve().parents[1] / ".github/workflows/buildapp.yml").read_text(encoding="utf-8")

class BuildWorkflowSafetyTests(unittest.TestCase):
    def test_01_manual_only(self):
        self.assertIn("  workflow_dispatch:", WORKFLOW)
        self.assertNotIn("  pull_request_target:", WORKFLOW)
    def test_02_opt_in_release(self):
        self.assertIn('if: ${{ inputs.create_release }}', WORKFLOW)
        self.assertIn("        default: false", WORKFLOW)
    def test_03_required_checksum(self):
        self.assertIn("decrypted_youtube_sha256:", WORKFLOW)
        self.assertIn('--sha256 "$IPA_SHA256"', WORKFLOW)
    def test_04_validate_before_build(self):
        self.assertIn("    needs: validate-inputs", WORKFLOW)
        self.assertIn("Run IPA validation unit tests", WORKFLOW)
    def test_05_write_only_in_separate_publish_job(self):
        before, after = WORKFLOW.split("\n  publish:\n", 1)
        self.assertNotIn("contents: write", before)
        self.assertEqual(after.count("contents: write"), 1)
    def test_06_reject_insecure_redirects(self):
        self.assertIn("--proto '=https' --proto-redir '=https'", WORKFLOW)
    def test_07_archive_validated_before_unzip(self):
        self.assertLess(WORKFLOW.index("main/scripts/build_checks.py ipa"), WORKFLOW.index("unzip -q main/YouTube.ipa"))
    def test_08_sensitive_action_refs_are_pinned(self):
        for line in WORKFLOW.splitlines():
            if "uses:" not in line:
                continue
            match = re.search(r"uses:\s+([\w-]+/[\w-]+)@(\S+)", line)
            if match:
                self.assertRegex(match.group(2), r"^[0-9a-f]{40}$", line)
    def test_09_third_party_runtime_source_pinned(self):
        self.assertRegex(WORKFLOW, r"repository: theos/theos\n\s+ref: [0-9a-f]{40}")
        self.assertRegex(WORKFLOW, r"repository: qnblackcat/theos-jailed\n\s+ref: [0-9a-f]{40}")
    def test_10_publisher_uses_no_checkout(self):
        self.assertNotIn("actions/checkout@", WORKFLOW.split("\n  publish:\n", 1)[1])
    def test_11_artifacts_explicitly_opted_in(self):
        self.assertIn("inputs.upload_artifact || inputs.create_release", WORKFLOW)
    def test_12_no_floating_gh_release_action(self):
        self.assertNotIn("action-gh-release@master", WORKFLOW)
        self.assertIn("gh release create", WORKFLOW)
    def test_13_build_uses_read_only_credentials(self):
        build = WORKFLOW.split("\n  build:\n", 1)[1].split("\n  publish:\n", 1)[0]
        self.assertIn("contents: read", build)
        self.assertNotIn("contents: write", build)

if __name__ == "__main__":
    unittest.main()
