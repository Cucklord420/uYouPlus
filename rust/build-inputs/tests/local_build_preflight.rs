#![cfg(unix)]

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    process::{Command, Output, Stdio},
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

const INFO_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleVersion</key><string>19.25.4</string></dict></plist>"#;
const MAX_LOCAL_IPA_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn write_ipa(path: &Path, extra: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    writer
        .start_file("Payload/YouTube.app/Info.plist", options)
        .unwrap();
    writer.write_all(INFO_PLIST).unwrap();
    for (name, contents) in extra {
        writer.start_file(name, options).unwrap();
        writer.write_all(contents).unwrap();
    }
    writer.finish().unwrap();
}

fn write_ipa_with_corrupt_member_data(path: &Path) {
    let file = File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    writer
        .start_file("Payload/YouTube.app/Info.plist", deflated)
        .unwrap();
    writer.write_all(INFO_PLIST).unwrap();
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    writer
        .start_file("Payload/YouTube.app/Corrupt.bin", stored)
        .unwrap();
    writer.write_all(b"intact member bytes").unwrap();
    writer.finish().unwrap();

    let file = File::open(path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();
    let member = archive.by_name("Payload/YouTube.app/Corrupt.bin").unwrap();
    let data_start = member.data_start().unwrap();
    drop(member);
    drop(archive);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(data_start)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xff;
    file.seek(SeekFrom::Start(data_start)).unwrap();
    file.write_all(&byte).unwrap();
}

fn executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).unwrap();
}

fn run_local_build(root: &Path, input: &str) -> (Output, std::path::PathBuf, std::path::PathBuf) {
    let bin = root.join("mock-bin");
    fs::create_dir_all(&bin).unwrap();
    let marker = root.join("make-invoked");
    let argument = root.join("make-ipa-argument");
    executable(
        &bin.join("make"),
        "#!/bin/sh\nset -eu\nprintf 'called\\n' > \"$MAKE_MARKER\"\nprintf '%s\\n' \"$3\" > \"$MAKE_ARGUMENT\"\nmkdir -p \"$THEOS_PACKAGE_DIR\"\nprintf 'synthetic package\\n' > \"$THEOS_PACKAGE_DIR/output.ipa\"\n",
    );
    executable(&bin.join("open"), "#!/bin/sh\nexit 0\n");
    let path = std::env::join_paths(std::iter::once(bin.clone()).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_uyouplus-inputs"))
        .arg("local-build")
        .current_dir(root)
        .env("PATH", path)
        .env("MAKE_MARKER", &marker)
        .env("MAKE_ARGUMENT", &argument)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{input}\n").as_bytes())
        .unwrap();
    (child.wait_with_output().unwrap(), marker, argument)
}

fn assert_blocked_before_make(root: &Path, input: &str) {
    let (output, marker, _) = run_local_build(root, input);
    assert!(
        !output.status.success(),
        "invalid input unexpectedly built: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "Theos make ran for rejected input");
    assert!(
        !root.join("packages").exists(),
        "package staging was created for rejected input"
    );
}

#[test]
fn missing_input_is_rejected_before_staging_or_make() {
    let temp = tempfile::tempdir().unwrap();

    assert_blocked_before_make(temp.path(), "missing.ipa");
}

#[test]
fn malformed_ipa_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("malformed.ipa"), b"not a ZIP archive").unwrap();

    assert_blocked_before_make(temp.path(), "malformed.ipa");
}

#[test]
fn unsafe_ipa_member_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    write_ipa(
        &temp.path().join("unsafe.ipa"),
        &[("Payload/YouTube.app/../../escape", b"outside")],
    );

    assert_blocked_before_make(temp.path(), "unsafe.ipa");
}

#[test]
fn case_folded_archive_path_collision_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    write_ipa(
        &temp.path().join("collision.ipa"),
        &[
            ("Payload/YouTube.app/Cache.bin", b"first"),
            ("Payload/YouTube.app/cache.bin", b"alias"),
        ],
    );

    assert_blocked_before_make(temp.path(), "collision.ipa");
}

#[test]
fn final_dot_archive_component_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    write_ipa(
        &temp.path().join("dot-component.ipa"),
        &[("Payload/YouTube.app/.", b"dot component")],
    );

    assert_blocked_before_make(temp.path(), "dot-component.ipa");
}

#[test]
fn corrupt_member_data_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    write_ipa_with_corrupt_member_data(&temp.path().join("corrupt.ipa"));

    assert_blocked_before_make(temp.path(), "corrupt.ipa");
}

#[test]
fn oversized_ipa_is_rejected_from_metadata_before_make() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("oversized.ipa");
    File::create(&path)
        .unwrap()
        .set_len(MAX_LOCAL_IPA_BYTES + 1)
        .unwrap();

    assert_blocked_before_make(temp.path(), "oversized.ipa");
}

#[test]
fn valid_ipa_path_with_spaces_reaches_make_as_one_argument() {
    let temp = tempfile::tempdir().unwrap();
    let input = "local input with spaces.ipa";
    write_ipa(&temp.path().join(input), &[]);

    let (output, marker, argument) = run_local_build(temp.path(), input);

    assert!(
        output.status.success(),
        "valid IPA was rejected: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(marker.exists(), "valid IPA did not reach Theos make");
    assert_eq!(
        fs::read_to_string(argument).unwrap(),
        format!("IPA={input}\n")
    );
}

#[test]
fn app_directory_checks_root_and_info_plist_but_trusts_contents() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("trusted app.app");
    fs::create_dir(&app).unwrap();
    fs::write(app.join("Info.plist"), INFO_PLIST).unwrap();
    fs::write(temp.path().join("nested target"), b"trusted contents").unwrap();
    symlink(
        temp.path().join("nested target"),
        app.join("nested symlink"),
    )
    .unwrap();

    let (output, marker, argument) = run_local_build(temp.path(), "trusted app.app");

    assert!(
        output.status.success(),
        "trusted app directory was rejected: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(marker.exists(), "trusted app directory did not reach make");
    assert_eq!(
        fs::read_to_string(argument).unwrap(),
        "IPA=trusted app.app\n"
    );
}

#[test]
fn app_without_a_nonempty_regular_info_plist_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("missing plist.app");
    fs::create_dir(&app).unwrap();
    assert_blocked_before_make(temp.path(), "missing plist.app");

    fs::write(app.join("Info.plist"), b"").unwrap();
    assert_blocked_before_make(temp.path(), "missing plist.app");
}

#[test]
fn symlinked_app_or_info_plist_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    let actual = temp.path().join("actual.app");
    fs::create_dir(&actual).unwrap();
    fs::write(actual.join("Info.plist"), INFO_PLIST).unwrap();
    symlink(&actual, temp.path().join("linked.app")).unwrap();
    assert_blocked_before_make(temp.path(), "linked.app");
    assert_blocked_before_make(temp.path(), "linked.app/");

    fs::remove_file(actual.join("Info.plist")).unwrap();
    fs::write(temp.path().join("external Info.plist"), INFO_PLIST).unwrap();
    symlink(
        temp.path().join("external Info.plist"),
        actual.join("Info.plist"),
    )
    .unwrap();
    assert_blocked_before_make(temp.path(), "actual.app");
}

#[test]
fn symlinked_ipa_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    let actual = temp.path().join("actual.ipa");
    write_ipa(&actual, &[]);
    symlink(&actual, temp.path().join("linked.ipa")).unwrap();

    assert_blocked_before_make(temp.path(), "linked.ipa");
}

#[test]
fn unsupported_or_wrong_type_input_is_rejected_before_make() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("archive.zip"), b"not accepted").unwrap();
    assert_blocked_before_make(temp.path(), "archive.zip");

    fs::write(temp.path().join("not a directory.app"), b"not accepted").unwrap();
    assert_blocked_before_make(temp.path(), "not a directory.app");

    fs::create_dir(temp.path().join("directory.ipa")).unwrap();
    assert_blocked_before_make(temp.path(), "directory.ipa");

    fs::write(temp.path().join("empty.ipa"), b"").unwrap();
    assert_blocked_before_make(temp.path(), "empty.ipa");
}
