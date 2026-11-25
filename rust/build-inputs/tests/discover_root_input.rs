#![cfg(unix)]

#[cfg(not(target_os = "macos"))]
use std::os::unix::ffi::OsStringExt;
use std::{
    ffi::OsString,
    fs,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::{Command, Output},
};
fn run(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uyouplus-inputs"))
        .arg("discover-root-input")
        .current_dir(root)
        .output()
        .expect("discovery helper should start")
}

#[test]
fn build_script_delegates_the_local_build_to_rust() {
    let script =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build.sh")).unwrap();

    for required_fragment in [
        "local-build",
        "cargo run --quiet",
        "rust/build-inputs/Cargo.toml",
        "--bin uyouplus-inputs",
    ] {
        assert!(
            script.contains(required_fragment),
            "build.sh must delegate the manual build to Rust: {required_fragment}"
        );
    }
    for shell_build_logic in ["make package", "shasum -a 256", "THEOS_PACKAGE_DIR="] {
        assert!(
            !script.contains(shell_build_logic),
            "manual build and artifact handling must remain in Rust: {shell_build_logic}"
        );
    }
}

fn assert_rejected_without_path(root: &Path) {
    let output = run(root);
    assert!(!output.status.success(), "invalid candidates must fail");
    assert!(
        output.stdout.is_empty(),
        "errors must not emit a candidate path"
    );
    assert!(
        !output.stderr.is_empty(),
        "errors should explain why discovery failed"
    );
}

#[test]
fn discovers_one_regular_ipa_and_preserves_spaces_and_newlines() {
    let temp = tempfile::tempdir().unwrap();
    let name = OsString::from("YouTube IPA\n(Original).ipa");
    fs::write(temp.path().join(Path::new(&name)), b"synthetic").unwrap();

    let output = run(temp.path());

    assert!(
        output.status.success(),
        "discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut expected = b"./".to_vec();
    expected.extend_from_slice(name.as_bytes());
    expected.push(0);
    assert_eq!(output.stdout, expected);
    assert!(output.stderr.is_empty());
}

#[test]
fn discovers_a_regular_ipa_whose_name_is_only_the_suffix() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join(".ipa"), b"synthetic").unwrap();

    let output = run(temp.path());

    assert!(
        output.status.success(),
        "discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"./.ipa\0");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn preserves_non_utf8_path_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let name = OsString::from_vec(b"YouTube-\xff.ipa".to_vec());
    fs::write(temp.path().join(Path::new(&name)), b"synthetic").unwrap();

    let output = run(temp.path());

    assert!(
        output.status.success(),
        "discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut expected = b"./".to_vec();
    expected.extend_from_slice(name.as_bytes());
    expected.push(0);
    assert_eq!(output.stdout, expected);
}

#[test]
fn discovers_one_app_directory_with_newlines() {
    let temp = tempfile::tempdir().unwrap();
    let name = OsString::from("YouTube App\nOriginal.app");
    fs::create_dir(temp.path().join(Path::new(&name))).unwrap();

    let output = run(temp.path());

    assert!(
        output.status.success(),
        "discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut expected = b"./".to_vec();
    expected.extend_from_slice(name.as_bytes());
    expected.push(0);
    assert_eq!(output.stdout, expected);
}

#[test]
fn discovers_an_app_directory_whose_name_is_only_the_suffix() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join(".app")).unwrap();

    let output = run(temp.path());

    assert!(
        output.status.success(),
        "discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"./.app\0");
}

#[test]
fn rejects_an_empty_root_without_output() {
    let temp = tempfile::tempdir().unwrap();
    assert_rejected_without_path(temp.path());
}

#[test]
fn rejects_multiple_valid_candidates_without_output() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("YouTube.ipa"), b"synthetic").unwrap();
    fs::create_dir(temp.path().join("YouTube.app")).unwrap();
    assert_rejected_without_path(temp.path());
}

#[test]
fn ignores_symlinked_ipa_candidates() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("actual-file"), b"synthetic").unwrap();
    symlink(
        temp.path().join("actual-file"),
        temp.path().join("linked.ipa"),
    )
    .unwrap();
    assert_rejected_without_path(temp.path());
}

#[test]
fn ignores_symlinked_app_candidates() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("actual-bundle")).unwrap();
    symlink(
        temp.path().join("actual-bundle"),
        temp.path().join("linked.app"),
    )
    .unwrap();
    assert_rejected_without_path(temp.path());
}

#[test]
fn ignores_wrong_entry_types() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("directory.ipa")).unwrap();
    fs::write(temp.path().join("regular-file.app"), b"synthetic").unwrap();
    assert_rejected_without_path(temp.path());
}

#[test]
fn does_not_search_inside_subdirectories() {
    let temp = tempfile::tempdir().unwrap();
    let nested = temp.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("YouTube.ipa"), b"synthetic").unwrap();
    assert_rejected_without_path(temp.path());
}
