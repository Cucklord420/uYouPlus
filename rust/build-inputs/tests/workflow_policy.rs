use regex::Regex;

const BUILD_WORKFLOW: &str = include_str!("../../../.github/workflows/buildapp.yml");
const VALIDATION_WORKFLOW: &str = include_str!("../../../.github/workflows/validate.yml");
const IPA_SOURCE: &str = include_str!("../src/bin/ipa.rs");

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
    assert!(IPA_SOURCE.contains("fn curl_command("));
    assert!(IPA_SOURCE.contains("\"--proto\""));
    assert!(IPA_SOURCE.contains("\"--proto-redir\""));
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
    assert!(prepare.contains("--bin ipa -- download --url-env YOUTUBE_URL"));
    assert!(prepare.contains("--output \"$staging/YouTube.ipa\""));
    assert!(prepare
        .contains("cargo run --quiet --manifest-path main/rust/build-inputs/Cargo.toml --bin ipa"));
    assert!(prepare.contains("--staging-dir \"$staging/extracted\""));
    assert!(prepare.contains("--payload-destination main/Payload"));
    assert!(!prepare.contains("curl "));
    assert!(!prepare.contains("unzip "));
    assert!(!prepare.contains("cp -R "));
    assert!(!prepare.contains("ditto "));
    assert!(!prepare.contains("tar "));
    assert!(!prepare.contains("mkdir main/Payload"));
    assert!(!prepare.contains("--output main/YouTube.ipa"));
}

#[test]
fn make_uses_the_bundle_promoted_after_manifest_verification() {
    let preparation = BUILD_WORKFLOW
        .find("--payload-destination main/Payload")
        .unwrap();
    let make = BUILD_WORKFLOW
        .find("make package THEOS_PACKAGE_SCHEME=rootless IPA=Payload/YouTube.app")
        .unwrap();
    let version_update = BUILD_WORKFLOW
        .find("YOUTUBE_VERSION = $youtube_version")
        .unwrap();

    assert!(preparation < version_update);
    assert!(version_update < make);
}

#[test]
fn rust_downloader_retains_the_approved_limits_and_retries() {
    assert!(IPA_SOURCE.contains("const MAX_IPA_DOWNLOAD_BYTES: u64 = 4 * BYTES_PER_GIB"));
    assert!(IPA_SOURCE.contains("const DISK_RESERVE_BYTES: u64 = 4 * BYTES_PER_GIB"));
    assert!(IPA_SOURCE.contains("const DOWNLOAD_ATTEMPTS: usize = 3"));
    assert!(IPA_SOURCE.contains("\"--max-time\""));
    assert!(IPA_SOURCE.contains("\"600\""));
    assert!(IPA_SOURCE.contains("--output"));
    assert!(IPA_SOURCE.contains("copy_stream_with_limit"));
    assert!(!IPA_SOURCE.contains("Content-Length"));
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
