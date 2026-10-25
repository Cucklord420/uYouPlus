use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VALID_VERSION: &str = "3.0.3";
const SYNTHETIC_AR: &[u8] = b"!<arch>\nfictional uYou package bytes";

fn tool_path() -> PathBuf {
    let mut path = env::current_exe().expect("integration test executable path");
    path.pop(); // deps
    path.pop(); // debug or release
    path.push(if cfg!(windows) { "uyou-deb.exe" } else { "uyou-deb" });
    assert!(path.is_file(), "uYou Debian Rust executable was built at {}", path.display());
    path
}

fn tool() -> Command {
    Command::new(tool_path())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn package_path(directory: &Path, version: &str) -> PathBuf {
    directory.join(format!("com.miro.uyou_{version}_iphoneos-arm.deb"))
}

fn run_ensure(directory: &Path, version: &str, sha256: &str) -> Output {
    tool()
        .args(["ensure", "--build-dir"])
        .arg(directory)
        .args(["--version", version, "--sha256", sha256])
        .output()
        .expect("run uyou-deb ensure")
}

fn build_synthetic_deb(root: &Path, complete: bool) -> PathBuf {
    let source = root.join(if complete { "complete-package" } else { "incomplete-package" });
    let control = source.join("DEBIAN");
    fs::create_dir_all(&control).unwrap();
    fs::write(
        control.join("control"),
        "Package: synthetic-uyou\nVersion: 3.0.3\nArchitecture: iphoneos-arm\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Fictional Debian archive\n",
    )
    .unwrap();
    if complete {
        let dylib = source.join("Library/MobileSubstrate/DynamicLibraries/uYou.dylib");
        fs::create_dir_all(dylib.parent().unwrap()).unwrap();
        fs::write(&dylib, b"NEW FICTIONAL DYLIB; NO PROPRIETARY MATERIAL").unwrap();
        let bundle = source.join("Library/Application Support/uYouBundle.bundle");
        fs::create_dir_all(&bundle).unwrap();
        fs::write(bundle.join("Info.plist"), b"Synthetic bundle fixture").unwrap();
    } else {
        let unrelated = source.join("usr/share/doc/synthetic-uyou/readme");
        fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
        fs::write(unrelated, b"This archive has no uYou payload").unwrap();
    }

    let archive = root.join(if complete { "complete.deb" } else { "incomplete.deb" });
    let output = Command::new("dpkg-deb")
        .arg("--build")
        .arg(&source)
        .arg(&archive)
        .output()
        .expect("dpkg-deb is installed");
    assert!(
        output.status.success(),
        "dpkg-deb fixture build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fs::read(&archive).unwrap().starts_with(b"!<arch>\n"));
    archive
}

fn has_dpkg_deb() -> bool {
    Command::new("dpkg-deb").arg("--version").output().is_ok()
}

fn compile_fake_curl(directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_curl.rs");
    let executable = directory.join(if cfg!(windows) { "curl.exe" } else { "curl" });
    let output = Command::new("rustc")
        .args(["--edition=2021"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("Rust compiler is on PATH for Cargo tests");
    assert!(
        output.status.success(),
        "fake curl compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

fn path_with(directory: &Path) -> std::ffi::OsString {
    let mut paths = vec![directory.to_path_buf()];
    if let Some(existing) = env::var_os("PATH") {
        paths.extend(env::split_paths(&existing));
    }
    env::join_paths(paths).expect("valid PATH")
}

#[test]
fn validate_accepts_a_reviewed_digest_and_safe_version() {
    let output = tool()
        .arg("validate")
        .env("UYOU_VERSION", VALID_VERSION)
        .env("UYOU_DEB_SHA256", "a".repeat(64))
        .output()
        .expect("run uyou-deb validate");

    assert!(
        output.status.success(),
        "valid inputs rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn validate_rejects_make_expression_as_plain_data() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("make-expression-ran");
    let expression = format!("$(shell touch {})", marker.display());
    let output = tool()
        .arg("validate")
        .env("UYOU_VERSION", expression)
        .env("UYOU_DEB_SHA256", "a".repeat(64))
        .output()
        .expect("run uyou-deb validate");

    assert!(!output.status.success(), "unsafe version was accepted");
    assert!(!marker.exists(), "version text was evaluated as a command");
}

#[test]
fn ensure_rejects_a_cached_package_with_the_wrong_digest() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(package_path(directory.path(), VALID_VERSION), SYNTHETIC_AR).unwrap();

    let output = run_ensure(directory.path(), VALID_VERSION, &"f".repeat(64));

    assert!(!output.status.success(), "mismatched cache was accepted");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("SHA-256"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn ensure_downloads_only_verified_bytes_and_leaves_no_temporary_file() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fictional-source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);

    let output = tool()
        .args(["ensure", "--build-dir"])
        .arg(directory.path())
        .args(["--version", VALID_VERSION, "--sha256", &digest(SYNTHETIC_AR)])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &source)
        .output()
        .expect("run uyou-deb ensure");

    assert!(
        output.status.success(),
        "verified synthetic download rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(package_path(directory.path(), VALID_VERSION)).unwrap(),
        SYNTHETIC_AR
    );
    assert_eq!(
        fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".download."))
            .count(),
        0,
        "temporary download file remained after promotion"
    );
}

#[test]
fn ensure_failed_download_never_publishes_partial_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fictional-source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);

    let output = tool()
        .args(["ensure", "--build-dir"])
        .arg(directory.path())
        .args(["--version", VALID_VERSION, "--sha256", &digest(SYNTHETIC_AR)])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &source)
        .env("SYNTHETIC_CURL_FAILURE", "1")
        .output()
        .expect("run uyou-deb ensure");

    assert!(!output.status.success(), "failed transfer was accepted");
    assert!(!package_path(directory.path(), VALID_VERSION).exists());
    assert_eq!(
        fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".download."))
            .count(),
        0,
        "partial transfer file remained after failure"
    );
}

#[test]
fn ensure_rejects_an_invalid_version_without_creating_a_package_path() {
    let directory = tempfile::tempdir().unwrap();
    let expression = "$(shell touch marker)";

    let output = run_ensure(directory.path(), expression, &"a".repeat(64));

    assert!(!output.status.success(), "unsafe version was accepted");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn extract_replaces_stale_payload_only_with_a_complete_archive() {
    if !has_dpkg_deb() {
        eprintln!("skipping: dpkg-deb is not installed");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let archive = build_synthetic_deb(directory.path(), true);
    let package = package_path(directory.path(), VALID_VERSION);
    fs::copy(&archive, &package).unwrap();

    let library = directory.path().join("Library");
    let old_dylib = library.join("MobileSubstrate/DynamicLibraries/uYou.dylib");
    fs::create_dir_all(old_dylib.parent().unwrap()).unwrap();
    fs::write(&old_dylib, b"OLD FICTIONAL DYLIB").unwrap();
    let stale_extra = library.join("StaleMarker.txt");
    fs::write(&stale_extra, b"must be removed").unwrap();

    let output = tool()
        .args(["extract", "--build-dir"])
        .arg(directory.path())
        .args(["--version", VALID_VERSION, "--sha256", &digest(&fs::read(&package).unwrap())])
        .output()
        .expect("run uyou-deb extract");

    assert!(
        output.status.success(),
        "complete synthetic archive rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(library.join("MobileSubstrate/DynamicLibraries/uYou.dylib")).unwrap(),
        b"NEW FICTIONAL DYLIB; NO PROPRIETARY MATERIAL"
    );
    assert!(library.join("Application Support/uYouBundle.bundle/Info.plist").is_file());
    assert!(!stale_extra.exists(), "stale payload survived full replacement");
}

#[test]
fn extract_rejects_incomplete_archive_and_preserves_the_old_payload() {
    if !has_dpkg_deb() {
        eprintln!("skipping: dpkg-deb is not installed");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let archive = build_synthetic_deb(directory.path(), false);
    let package = package_path(directory.path(), VALID_VERSION);
    fs::copy(&archive, &package).unwrap();

    let library = directory.path().join("Library");
    let old_dylib = library.join("MobileSubstrate/DynamicLibraries/uYou.dylib");
    fs::create_dir_all(old_dylib.parent().unwrap()).unwrap();
    fs::write(&old_dylib, b"OLD FICTIONAL DYLIB").unwrap();
    let old_bytes = fs::read(&old_dylib).unwrap();

    let output = tool()
        .args(["extract", "--build-dir"])
        .arg(directory.path())
        .args(["--version", VALID_VERSION, "--sha256", &digest(&fs::read(&package).unwrap())])
        .output()
        .expect("run uyou-deb extract");

    assert!(!output.status.success(), "incomplete archive was installed");
    assert_eq!(fs::read(old_dylib).unwrap(), old_bytes);
    assert!(library.is_dir());
}
