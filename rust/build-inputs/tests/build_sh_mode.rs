#[cfg(unix)]
#[test]
fn build_script_can_be_started_with_its_documented_direct_invocation() {
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let launcher = repository.join("build.sh");
    let unrelated_directory = tempfile::tempdir().unwrap();
    let output = Command::new(launcher)
        .current_dir(unrelated_directory.path())
        .env("UYOUPLUS_INPUTS_BIN", "/usr/bin/false")
        .stdin(Stdio::null())
        .output()
        .expect("directly execute the documented build.sh entry point");

    assert!(
        !output.status.success(),
        "empty discovery should stop before a build"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Could not discover one root-level"),
        "the script should run and reject empty discovery: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
