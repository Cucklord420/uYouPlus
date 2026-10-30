#![cfg(unix)]

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tempfile::TempDir;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

const INFO_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleVersion</key><string>19.25.4</string></dict></plist>"#;

fn write_ipa(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let file = fs::File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    writer
        .start_file(
            "Payload/YouTube.app/Info.plist",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
    writer.write_all(INFO_PLIST).unwrap();
    writer.finish().unwrap();
}

fn write_app(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::write(path.join("Info.plist"), INFO_PLIST).unwrap();
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    script: PathBuf,
    make_log: PathBuf,
    bin: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let script = root.join("build.sh");
        fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build.sh"),
            &script,
        )
        .unwrap();

        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        let stub_source = root.join("make_stub.rs");
        fs::write(
            &stub_source,
            r#"
use std::{env, fs, process};
use std::os::unix::ffi::OsStrExt;

fn main() {
    let log = env::var_os("MAKE_LOG").expect("MAKE_LOG");
    let ipa = env::args_os()
        .skip(1)
        .find(|arg| arg.as_bytes().starts_with(b"IPA="))
        .expect("make did not receive IPA=");
    fs::write(log, &ipa.as_bytes()[4..]).unwrap();
    process::exit(7);
}
"#,
        )
        .unwrap();
        let make_stub = bin.join("make");
        let compiled = Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&stub_source)
            .arg("-o")
            .arg(&make_stub)
            .output()
            .expect("rustc must be available while running Cargo tests");
        assert!(
            compiled.status.success(),
            "could not compile Rust make stub: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&make_stub, fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            _temp: temp,
            root: root.clone(),
            script,
            make_log: root.join("make-args"),
            bin,
        }
    }

    fn run(&self) -> std::process::Output {
        self.run_with_input(b"\n", Some(env!("CARGO_BIN_EXE_uyouplus-inputs")))
    }

    fn run_with_input(&self, input: &[u8], helper_bin: Option<&str>) -> std::process::Output {
        let mut path_entries = vec![self.bin.clone()];
        path_entries.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        let path = env::join_paths(path_entries).unwrap();

        let mut command = Command::new("/bin/bash");
        command
            .arg(&self.script)
            .current_dir(&self.root)
            .env("PATH", path)
            .env("MAKE_LOG", &self.make_log)
            .env("UYOUPLUS_BUILD_BIN", env!("CARGO_BIN_EXE_uyouplus-inputs"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(helper_bin) = helper_bin {
            command.env("UYOUPLUS_INPUTS_BIN", helper_bin);
        }
        let mut child = command
            .spawn()
            .expect("/bin/bash is required for build.sh integration tests");
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn invoked_ipa(&self) -> Option<Vec<u8>> {
        fs::read(&self.make_log).ok()
    }
}

#[test]
fn discovers_a_root_level_app_directory_without_newline_splitting() {
    let fixture = Fixture::new();
    let app = fixture.root.join("YouTube App\nOriginal.app");
    write_app(&app);

    let _output = fixture.run();

    let expected: &[u8] = b"./YouTube App\nOriginal.app";
    assert_eq!(
        fixture.invoked_ipa().as_deref(),
        Some(expected),
        "the root .app directory must reach make as one quoted path"
    );
}

#[test]
fn discovers_a_root_level_regular_ipa_file() {
    let fixture = Fixture::new();
    write_ipa(&fixture.root.join("YouTube.ipa"));

    let _output = fixture.run();

    assert_eq!(
        fixture.invoked_ipa().as_deref(),
        Some(&b"./YouTube.ipa"[..]),
        "the root .ipa file must reach make as one quoted path"
    );
}

#[test]
fn rejects_an_empty_root_without_invoking_make() {
    let fixture = Fixture::new();

    let output = fixture.run();

    assert!(!output.status.success(), "an empty root must be rejected");
    assert!(
        fixture.invoked_ipa().is_none(),
        "make must not run when there are no candidates"
    );
}

#[test]
fn treats_regular_ipa_and_app_directory_as_two_candidates() {
    let fixture = Fixture::new();
    write_ipa(&fixture.root.join("YouTube.ipa"));
    write_app(&fixture.root.join("YouTube.app"));

    let output = fixture.run();

    assert!(
        !output.status.success(),
        "multiple candidates must be rejected"
    );
    assert!(
        fixture.invoked_ipa().is_none(),
        "make must not run when candidate selection is ambiguous"
    );
}

#[test]
fn ignores_symlinked_app_candidates() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let actual = fixture.root.join("actual-bundle");
    let link = fixture.root.join("linked.app");
    fs::create_dir(&actual).unwrap();
    symlink(&actual, &link).unwrap();

    let output = fixture.run();

    assert!(
        !output.status.success(),
        "a symlink is not an app directory"
    );
    assert!(
        fixture.invoked_ipa().is_none(),
        "make must not receive a symlinked app candidate"
    );
}

#[test]
fn ignores_ipa_directories_and_app_regular_files() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("not-an-ipa.ipa")).unwrap();
    fs::write(fixture.root.join("not-an-app.app"), b"synthetic").unwrap();

    let output = fixture.run();

    assert!(
        !output.status.success(),
        "wrong candidate types must be rejected"
    );
    assert!(
        fixture.invoked_ipa().is_none(),
        "make must not run when no valid candidate exists"
    );
}

#[test]
fn explicit_operator_path_does_not_require_the_discovery_helper() {
    let fixture = Fixture::new();
    let operator_input = fixture.root.join("operator path with spaces/YouTube.ipa");
    write_ipa(&operator_input);
    let operator_input = operator_input.to_string_lossy();
    let _output = fixture.run_with_input(
        format!("{operator_input}\n").as_bytes(),
        Some("/missing/uyouplus-inputs-helper"),
    );

    assert_eq!(
        fixture.invoked_ipa().as_deref(),
        Some(operator_input.as_bytes())
    );
}

#[test]
fn helper_startup_failure_stops_before_make() {
    let fixture = Fixture::new();
    let output = fixture.run_with_input(b"\n", Some("/missing/uyouplus-inputs-helper"));

    assert!(!output.status.success());
    assert!(fixture.invoked_ipa().is_none());
}
