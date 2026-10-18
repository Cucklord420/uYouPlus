// Regression: the inherited local Theos launcher must report a failed build to its caller.
// This uses a disposable cwd and an inert failing executable; no IPA is downloaded,
// produced, extracted, signed, or installed.

#[cfg(unix)]
#[test]
fn local_build_failure_returns_nonzero_status() {
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::process::{Command, Stdio};

    let root = tempfile::tempdir().expect("temporary test directory");
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).expect("mock command directory");

    // /usr/bin/false is present on the GitHub-hosted macOS and Ubuntu runners.
    symlink("/usr/bin/false", bin.join("make")).expect("inert make replacement");
    let launcher = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../build.sh");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var_os("PATH").unwrap_or_default().to_string_lossy()
    );

    let mut process = Command::new("bash")
        .arg(launcher)
        .current_dir(root.path())
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start local build launcher");
    process
        .stdin
        .take()
        .expect("launcher stdin")
        .write_all(b"fake-input.ipa\n")
        .expect("supply synthetic path");

    let result = process.wait_with_output().expect("launcher completed");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout.contains("Failed building uYouPlus"),
        "expected failure diagnostic; stdout={stdout:?}, stderr={:?}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        !result.status.success(),
        "a failing make must not return success; status={:?}, stdout={stdout:?}",
        result.status
    );
}

#[cfg(unix)]
mod output_artifact_tests {
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const PRODUCE_ONE: &str =
        "mkdir -p packages\nprintf 'synthetic archive bytes\n' > packages/out.ipa\n";

    fn stub(bin: &Path, name: &str, body: &str) {
        let path = bin.join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
    }

    // Real checked-in build.sh and real system shasum (except in negative hash
    // tests). Only make and the cosmetic open command are replaced.
    fn run(
        make_body: &str,
        existing: &[(&str, &[u8])],
        hash_override: Option<&str>,
    ) -> (bool, String, String) {
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for (path, bytes) in existing {
            let full = temp.path().join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, bytes).unwrap();
        }
        // Files supplied above are deliberately older than the build start.
        std::thread::sleep(Duration::from_millis(20));

        stub(&bin, "make", make_body);
        stub(&bin, "open", "exit 1");
        if let Some(body) = hash_override {
            stub(&bin, "shasum", body);
        }
        let launcher = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build.sh");
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var_os("PATH").unwrap_or_default().to_string_lossy()
        );
        let mut child = Command::new("bash")
            .arg(launcher)
            .current_dir(temp.path())
            .env("PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic-input.ipa\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn rejects(make_body: &str, existing: &[(&str, &[u8])], hash: Option<&str>) {
        let (success, stdout, stderr) = run(make_body, existing, hash);
        assert!(!success, "false success: stdout={stdout:?} stderr={stderr:?}");
        assert!(
            stdout.contains("Build output rejected"),
            "expected artifact-verification failure: stdout={stdout:?}, stderr={stderr:?}"
        );
    }

    #[test]
    fn make_success_with_no_ipa_is_not_successful_build() {
        rejects("exit 0", &[], None);
    }

    #[test]
    fn make_success_with_two_ipas_is_not_successful_build() {
        rejects(
            "mkdir -p packages\nprintf a > packages/a.ipa\nprintf b > packages/b.ipa",
            &[],
            None,
        );
    }

    #[test]
    fn make_success_with_empty_ipa_is_rejected() {
        rejects("mkdir -p packages\n: > packages/out.ipa", &[], None);
    }

    #[test]
    fn make_success_cannot_reuse_stale_ipa() {
        rejects("exit 0", &[("packages/old.ipa", b"old archive")], None);
    }

    #[test]
    fn make_success_with_extra_stale_ipa_is_ambiguous() {
        rejects(PRODUCE_ONE, &[("packages/stale.ipa", b"stale archive")], None);
    }

    #[test]
    fn make_success_cannot_accept_symlinked_ipa() {
        rejects(
            "mkdir -p packages\nprintf data > source.bin\nln -s ../source.bin packages/out.ipa",
            &[],
            None,
        );
    }

    #[test]
    fn hash_command_failure_cannot_report_success() {
        rejects(PRODUCE_ONE, &[], Some("exit 13"));
    }

    #[test]
    fn malformed_hash_output_cannot_report_success() {
        rejects(
            PRODUCE_ONE,
            &[],
            Some("printf 'invalid-digest  packages/out.ipa\\n'"),
        );
    }

    #[test]
    fn fresh_single_ipa_with_valid_digest_succeeds_even_if_open_fails() {
        let (success, stdout, stderr) = run(PRODUCE_ONE, &[], None);
        let expected = format!("{:x}", Sha256::digest(b"synthetic archive bytes\n"));
        assert!(
            success,
            "expected success for the sole new artifact: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains(&expected) && stdout.contains("packages/out.ipa"),
            "must report the digest for the actual output path: stdout={stdout:?}"
        );
    }
}
