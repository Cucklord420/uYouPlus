use regex::Regex;

const BUILD_WORKFLOW: &str = include_str!("../../../.github/workflows/buildapp.yml");
const VALIDATION_WORKFLOW: &str = include_str!("../../../.github/workflows/validate.yml");

#[test]
fn builder_is_manual_and_release_is_opt_in() {
    assert!(BUILD_WORKFLOW.contains("  workflow_dispatch:"));
    assert!(!BUILD_WORKFLOW.contains("  pull_request_target:"));
    assert!(BUILD_WORKFLOW.contains("if: ${{ inputs.create_release }}"));
    assert!(BUILD_WORKFLOW.contains("        default: false"));
}

#[test]
fn checksum_is_required_and_validated_before_build() {
    assert!(BUILD_WORKFLOW.contains("decrypted_youtube_sha256:"));
    assert!(BUILD_WORKFLOW.contains("--sha256 \"$IPA_SHA256\""));
    assert!(BUILD_WORKFLOW.contains("    needs: validate-inputs"));
    assert!(BUILD_WORKFLOW.contains("cargo test --manifest-path rust/build-inputs/Cargo.toml"));
}

#[test]
fn publish_write_permission_is_isolated() {
    let (build, publish) = BUILD_WORKFLOW.split_once("\n  publish:\n").unwrap();
    assert!(!build.contains("contents: write"));
    assert_eq!(publish.matches("contents: write").count(), 1);
}

#[test]
fn download_rejects_insecure_redirects() {
    assert!(BUILD_WORKFLOW.contains("--proto '=https' --proto-redir '=https'"));
}

#[test]
fn ipa_is_validated_and_prepared_by_rust_in_runner_temp() {
    let start = BUILD_WORKFLOW
        .find("      - name: Prepare YouTube IPA")
        .unwrap();
    let rest = &BUILD_WORKFLOW[start..];
    let end = rest.find("\n      - name: Fix compiling").unwrap();
    let prepare = &rest[..end];

    assert!(prepare.contains("mktemp -d \"${RUNNER_TEMP}/youtube-ipa-XXXXXXXX\""));
    assert!(prepare.contains("trap 'rm -rf -- \"$staging\"' EXIT"));
    assert!(prepare
        .contains("cargo run --quiet --manifest-path main/rust/build-inputs/Cargo.toml --bin ipa"));
    assert!(prepare.contains("--staging-dir \"$staging/extracted\""));
    assert!(prepare.contains("--payload-destination main/Payload"));
    assert!(prepare.contains("--proto '=https' --proto-redir '=https'"));
    assert!(!prepare.contains("unzip "));
    assert!(!prepare.contains("cp -R "));
    assert!(!prepare.contains("ditto "));
    assert!(!prepare.contains("tar "));
    assert!(!prepare.contains("mkdir main/Payload"));
    assert!(!prepare.contains("--output main/YouTube.ipa"));
}

#[test]
fn validation_workflows_do_not_run_python() {
    for workflow in [BUILD_WORKFLOW, VALIDATION_WORKFLOW] {
        assert!(!workflow.contains("python3"));
        assert!(!workflow.contains("unittest"));
        assert!(workflow.contains("cargo test --manifest-path rust/build-inputs/Cargo.toml"));
    }
    assert!(!VALIDATION_WORKFLOW.contains("scripts/build_checks.py"));
}

#[test]
fn action_references_are_pinned_to_commits() {
    let reference = Regex::new(r"uses:\s+([\w-]+/[\w-]+)@(\S+)").unwrap();
    let commit = Regex::new(r"^[0-9a-f]{40}$").unwrap();
    for line in BUILD_WORKFLOW.lines() {
        if let Some(captures) = reference.captures(line) {
            assert!(
                commit.is_match(&captures[2]),
                "unpinned action reference: {line}"
            );
        }
    }
}

#[test]
fn third_party_tool_sources_are_pinned_to_commits() {
    let source = Regex::new(r"repository: ([\w-]+/[\w-]+)\n\s+ref: [0-9a-f]{40}").unwrap();
    for (repository, workflow) in [
        ("theos/theos", BUILD_WORKFLOW),
        ("qnblackcat/theos-jailed", BUILD_WORKFLOW),
        ("theos/sdks", BUILD_WORKFLOW),
    ] {
        assert!(
            source.captures_iter(workflow).any(|captures| captures
                .get(1)
                .is_some_and(|name| name.as_str() == repository)),
            "{repository}"
        );
    }
    assert!(!BUILD_WORKFLOW.contains("git clone -n --depth=1"));
}

#[test]
fn publisher_does_not_checkout_source() {
    let publish = BUILD_WORKFLOW.split_once("\n  publish:\n").unwrap().1;
    assert!(!publish.contains("actions/checkout@"));
}

#[test]
fn artifact_upload_is_explicitly_opted_in() {
    assert!(BUILD_WORKFLOW.contains("inputs.upload_artifact || inputs.create_release"));
}

#[test]
fn release_creation_does_not_use_a_floating_action() {
    assert!(!BUILD_WORKFLOW.contains("action-gh-release@master"));
    assert!(BUILD_WORKFLOW.contains("gh release create"));
}

#[test]
fn build_job_uses_read_only_credentials() {
    let build = BUILD_WORKFLOW
        .split_once("\n  build:\n")
        .unwrap()
        .1
        .split_once("\n  publish:\n")
        .unwrap()
        .0;
    assert!(build.contains("contents: read"));
    assert!(!build.contains("contents: write"));
}
