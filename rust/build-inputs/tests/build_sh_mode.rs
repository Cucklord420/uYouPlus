use std::path::PathBuf;
use std::process::Command;

#[test]
fn build_script_is_stored_as_executable_for_direct_invocation() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("git")
        .args(["ls-files", "--stage", "--", "build.sh"])
        .current_dir(&repository)
        .output()
        .expect("git is available in the source checkout");

    assert!(
        output.status.success(),
        "could not inspect the tracked build.sh mode: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let entry = String::from_utf8_lossy(&output.stdout);
    let mode = entry.split_whitespace().next().unwrap_or("");
    assert_eq!(
        mode, "100755",
        "build.sh documents direct invocation with ./build.sh"
    );
}
