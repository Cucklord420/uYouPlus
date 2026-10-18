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
