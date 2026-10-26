#![cfg(unix)]

use std::{
    env, fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};
use tempfile::TempDir;

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
        let mut path_entries = vec![self.bin.clone()];
        path_entries.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        let path = env::join_paths(path_entries).unwrap();

        let mut child = Command::new("/bin/bash")
            .arg(&self.script)
            .current_dir(&self.root)
            .env("PATH", path)
            .env("MAKE_LOG", &self.make_log)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("/bin/bash is required for build.sh integration tests");
        child.stdin.take().unwrap().write_all(b"\n").unwrap();
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
    fs::create_dir(&app).unwrap();

    let _output = fixture.run();

    let expected: &[u8] = b"./YouTube App\nOriginal.app";
    assert_eq!(
        fixture.invoked_ipa().as_deref(),
        Some(expected),
        "the root .app directory must reach make as one quoted path"
    );
}

#[test]
fn treats_regular_ipa_and_app_directory_as_two_candidates() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("YouTube.ipa"), b"synthetic").unwrap();
    fs::create_dir(fixture.root.join("YouTube.app")).unwrap();

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
