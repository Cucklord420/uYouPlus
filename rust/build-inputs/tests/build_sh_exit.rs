// Regression: the inherited local Theos launcher must report a failed build to its caller.
// This uses a disposable cwd and an inert failing executable; no IPA is downloaded,
// signed, or installed.

#[cfg(unix)]
fn write_test_ipa(path: &std::path::Path) {
    use std::fs::File;
    use std::io::Write;
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

    let file = File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    writer
        .start_file(
            "Payload/YouTube.app/Info.plist",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
    writer
        .write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleVersion</key><string>19.25.4</string></dict></plist>"#,
        )
        .unwrap();
    writer.finish().unwrap();
}

#[cfg(unix)]
#[test]
fn local_build_failure_returns_nonzero_status() {
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::process::{Command, Stdio};

    let root = tempfile::tempdir().expect("temporary test directory");
    write_test_ipa(&root.path().join("fake-input.ipa"));
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).expect("mock command directory");

    // /usr/bin/false is present on the GitHub-hosted macOS and Ubuntu runners.
    symlink("/usr/bin/false", bin.join("make")).expect("inert make replacement");
    let launcher = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build.sh");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var_os("PATH")
            .unwrap_or_default()
            .to_string_lossy()
    );

    let mut process = Command::new("bash")
        .arg(launcher)
        .current_dir(root.path())
        .env("PATH", path)
        .env("UYOUPLUS_BUILD_BIN", env!("CARGO_BIN_EXE_uyouplus-inputs"))
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

    const PRODUCE_ONE: &str = "mkdir -p \"$THEOS_PACKAGE_DIR\"\nprintf 'synthetic archive bytes\n' > \"$THEOS_PACKAGE_DIR/out.ipa\"\n";

    fn stub(bin: &Path, name: &str, body: &str) {
        let path = bin.join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
    }

    // Real checked-in build.sh and Rust CLI. The shasum stub proves that the
    // reported digest does not depend on an external hash executable.
    fn run(
        make_body: &str,
        existing: &[(&str, &[u8])],
        hash_override: Option<&str>,
    ) -> (tempfile::TempDir, bool, String, String) {
        let temp = tempfile::tempdir().unwrap();
        super::write_test_ipa(&temp.path().join("synthetic input.ipa"));
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for (path, bytes) in existing {
            let full = temp.path().join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, bytes).unwrap();
        }
        stub(&bin, "make", make_body);
        if let Some(body) = hash_override {
            stub(&bin, "shasum", body);
        }
        let launcher = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build.sh");
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var_os("PATH")
                .unwrap_or_default()
                .to_string_lossy()
        );
        let mut child = Command::new("bash")
            .arg(launcher)
            .current_dir(temp.path())
            .env("PATH", path)
            .env("UYOUPLUS_BUILD_BIN", env!("CARGO_BIN_EXE_uyouplus-inputs"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic input.ipa\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            temp,
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn rejects(make_body: &str, existing: &[(&str, &[u8])], hash: Option<&str>) {
        let (_temp, success, stdout, stderr) = run(make_body, existing, hash);
        assert!(
            !success,
            "false success: stdout={stdout:?} stderr={stderr:?}"
        );
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
    fn input_path_with_spaces_remains_one_make_argument() {
        let body = "test \"$3\" = 'IPA=synthetic input.ipa' || exit 42\nmkdir -p \"$THEOS_PACKAGE_DIR\"\nprintf 'synthetic archive bytes\\n' > \"$THEOS_PACKAGE_DIR/out.ipa\"";
        let (_temp, success, stdout, stderr) = run(body, &[], None);
        assert!(
            success,
            "make did not receive the spaced input as one argument: stdout={stdout:?} stderr={stderr:?}"
        );
    }

    #[test]
    fn make_success_with_two_ipas_is_not_successful_build() {
        rejects(
            "mkdir -p \"$THEOS_PACKAGE_DIR\"\nprintf a > \"$THEOS_PACKAGE_DIR/a.ipa\"\nprintf b > \"$THEOS_PACKAGE_DIR/b.ipa\"",
            &[],
            None,
        );
    }

    #[test]
    fn make_success_with_empty_ipa_is_rejected() {
        rejects(
            "mkdir -p \"$THEOS_PACKAGE_DIR\"\n: > \"$THEOS_PACKAGE_DIR/out.ipa\"",
            &[],
            None,
        );
    }

    #[test]
    fn make_success_cannot_reuse_stale_ipa() {
        rejects("exit 0", &[("packages/old.ipa", b"old archive")], None);
    }

    #[test]
    fn build_with_an_existing_same_name_ipa_preserves_old_output() {
        let (temp, success, stdout, stderr) =
            run(PRODUCE_ONE, &[("packages/out.ipa", b"stale archive")], None);
        assert!(
            success,
            "fresh build failed: stdout={stdout:?} stderr={stderr:?}"
        );
        let packages = temp.path().join("packages");
        assert_eq!(
            fs::read(packages.join("out.ipa")).unwrap(),
            b"stale archive"
        );
        let outputs: Vec<_> = fs::read_dir(&packages)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "ipa")
            })
            .collect();
        assert_eq!(
            outputs.len(),
            2,
            "fresh output must not overwrite the prior IPA"
        );
        let fresh = outputs
            .iter()
            .find(|entry| entry.file_name() != "out.ipa")
            .expect("fresh output with a unique name");
        assert_eq!(
            fs::read(fresh.path()).unwrap(),
            b"synthetic archive bytes\n"
        );
        let expected = format!("{:x}", Sha256::digest(b"synthetic archive bytes\n"));
        let fresh_name = fresh.file_name().to_string_lossy().into_owned();
        assert!(
            stdout.contains(&expected),
            "missing fresh artifact digest: {stdout:?}"
        );
        assert!(
            stdout.contains(&fresh_name),
            "reported path must identify the new IPA: {stdout:?}"
        );
    }

    #[test]
    fn make_success_cannot_accept_symlinked_ipa() {
        rejects(
            "mkdir -p \"$THEOS_PACKAGE_DIR\"\nprintf data > source.bin\nln -s \"$PWD/source.bin\" \"$THEOS_PACKAGE_DIR/out.ipa\"",
            &[],
            None,
        );
    }

    #[test]
    fn failed_make_cleans_its_isolated_package_directory() {
        let (temp, success, stdout, stderr) = run("exit 13", &[], None);
        assert!(!success, "failed make unexpectedly succeeded");
        assert!(
            stdout.contains("Failed building uYouPlus"),
            "missing build failure message: stdout={stdout:?} stderr={stderr:?}"
        );
        let packages = temp.path().join("packages");
        assert_eq!(
            fs::read_dir(packages).unwrap().count(),
            0,
            "failed builds must remove their private package staging directory"
        );
    }

    #[test]
    fn rust_digest_is_independent_of_external_hash_command() {
        let (temp, success, stdout, stderr) = run(PRODUCE_ONE, &[], Some("exit 13"));
        let expected = format!("{:x}", Sha256::digest(b"synthetic archive bytes\n"));
        assert!(
            success,
            "the Rust digest must not depend on shasum: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains(&expected) && stdout.contains("packages/out.ipa"),
            "must report the Rust-computed digest and artifact path: stdout={stdout:?}"
        );
        assert_eq!(
            fs::read(temp.path().join("packages/out.ipa")).unwrap(),
            b"synthetic archive bytes\n"
        );
    }

    #[test]
    fn fresh_single_ipa_with_valid_digest_succeeds_even_if_open_fails() {
        let (_temp, success, stdout, stderr) = run(PRODUCE_ONE, &[], None);
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
