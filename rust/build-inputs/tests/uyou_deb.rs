use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VALID_VERSION: &str = "3.0.3";
const SYNTHETIC_AR: &[u8] = b"!<arch>\nfictional uYou package bytes";
const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;

fn tool_path() -> PathBuf {
    let mut path = env::current_exe().expect("integration test executable path");
    path.pop(); // deps
    path.pop(); // debug or release
    path.push(if cfg!(windows) {
        "uyou-deb.exe"
    } else {
        "uyou-deb"
    });
    assert!(
        path.is_file(),
        "uYou Debian Rust executable was built at {}",
        path.display()
    );
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
    let source = root.join(if complete {
        "complete-package"
    } else {
        "incomplete-package"
    });
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

    let archive = root.join(if complete {
        "complete.deb"
    } else {
        "incomplete.deb"
    });
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

fn make_executable() -> Option<&'static str> {
    Command::new("make")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("GNU Make")
        })
        .map(|_| "make")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).unwrap();
        if metadata.is_dir() {
            copy_directory(&source_path, &destination_path);
        } else if metadata.is_file() {
            fs::copy(source_path, destination_path).unwrap();
        }
    }
}

fn prepare_make_checkout(root: &Path) {
    fs::copy(repo_root().join("Makefile"), root.join("Makefile")).unwrap();
    copy_directory(
        &repo_root().join("Localizations/uYouPlus.bundle"),
        &root.join("Localizations/uYouPlus.bundle"),
    );
    fs::create_dir_all(root.join("Tweaks/uYou")).unwrap();
    let makefiles = root.join("fake-theos/makefiles");
    fs::create_dir_all(&makefiles).unwrap();
    for name in ["common.mk", "aggregate.mk", "tweak.mk"] {
        fs::write(makefiles.join(name), "").unwrap();
    }
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
fn validate_rejects_missing_or_malformed_digest_and_version() {
    let valid_digest = "a".repeat(64);
    let cases = vec![
        (VALID_VERSION.to_string(), String::new()),
        (VALID_VERSION.to_string(), "not-a-digest".to_string()),
        (VALID_VERSION.to_string(), "a".repeat(63)),
        (String::new(), valid_digest.clone()),
        ("1".repeat(41), valid_digest.clone()),
        ("3.0.3;touch".to_string(), valid_digest),
    ];
    for (version, digest) in cases {
        let output = tool()
            .arg("validate")
            .env("UYOU_VERSION", &version)
            .env("UYOU_DEB_SHA256", &digest)
            .output()
            .expect("run uyou-deb validate");
        assert!(
            !output.status.success(),
            "accepted version={version:?} digest={digest:?}"
        );
    }
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
fn ensure_accepts_a_valid_cached_synthetic_ar_archive() {
    let directory = tempfile::tempdir().unwrap();
    let package = package_path(directory.path(), VALID_VERSION);
    fs::write(&package, SYNTHETIC_AR).unwrap();

    let output = run_ensure(directory.path(), VALID_VERSION, &digest(SYNTHETIC_AR));

    assert!(
        output.status.success(),
        "valid cached package rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(package).unwrap(), SYNTHETIC_AR);
}

#[test]
fn ensure_rejects_empty_http_and_non_archive_cache_entries() {
    for bytes in [b"".as_slice(), b"HTTP 404 not found", b"not an ar archive"] {
        let directory = tempfile::tempdir().unwrap();
        fs::write(package_path(directory.path(), VALID_VERSION), bytes).unwrap();
        let output = run_ensure(directory.path(), VALID_VERSION, &digest(bytes));
        assert!(!output.status.success(), "accepted cached bytes {bytes:?}");
    }
}

#[test]
fn ensure_rejects_directory_at_cached_package_path() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(package_path(directory.path(), VALID_VERSION)).unwrap();

    let output = run_ensure(directory.path(), VALID_VERSION, &"a".repeat(64));

    assert!(
        !output.status.success(),
        "accepted a directory as a package"
    );
}

#[test]
fn ensure_rejects_oversized_cached_package_before_hashing_it() {
    let directory = tempfile::tempdir().unwrap();
    let package = package_path(directory.path(), VALID_VERSION);
    let file = fs::File::create(&package).unwrap();
    file.set_len(MAX_PACKAGE_BYTES + 1).unwrap();

    let output = run_ensure(directory.path(), VALID_VERSION, &"a".repeat(64));

    assert!(!output.status.success(), "accepted a package over 512 MiB");
    assert!(String::from_utf8_lossy(&output.stderr).contains("512 MiB"));
}

#[cfg(unix)]
#[test]
fn ensure_rejects_a_symlinked_cached_package() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    symlink(&source, package_path(directory.path(), VALID_VERSION)).unwrap();

    let output = run_ensure(directory.path(), VALID_VERSION, &digest(SYNTHETIC_AR));

    assert!(
        !output.status.success(),
        "accepted a symlink as the cached package"
    );
}

#[cfg(unix)]
#[test]
fn ensure_rejects_a_symlinked_package_parent() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    let linked = directory.path().join("linked");
    fs::create_dir(&real).unwrap();
    fs::write(package_path(&real, VALID_VERSION), SYNTHETIC_AR).unwrap();
    symlink(&real, &linked).unwrap();

    let output = run_ensure(&linked, VALID_VERSION, &digest(SYNTHETIC_AR));

    assert!(
        !output.status.success(),
        "accepted a symlinked package parent"
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
        .args([
            "--version",
            VALID_VERSION,
            "--sha256",
            &digest(SYNTHETIC_AR),
        ])
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
fn ensure_retries_partial_download_without_appending_its_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fictional-source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);
    let attempts = directory.path().join("curl-attempts");

    let output = tool()
        .args(["ensure", "--build-dir"])
        .arg(directory.path())
        .args([
            "--version",
            VALID_VERSION,
            "--sha256",
            &digest(SYNTHETIC_AR),
        ])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &source)
        .env("SYNTHETIC_CURL_PARTIAL_RETRY", "1")
        .env("SYNTHETIC_CURL_ATTEMPT_MARKER", &attempts)
        .output()
        .expect("run uyou-deb ensure");

    assert!(
        output.status.success(),
        "partial transfer was not safely retried: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(attempts).unwrap(), "2");
    assert_eq!(
        fs::read(package_path(directory.path(), VALID_VERSION)).unwrap(),
        SYNTHETIC_AR
    );
}

#[test]
fn ensure_honors_retry_after_before_retrying() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fictional-source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);
    let attempts = directory.path().join("curl-attempts");
    let retry_marker = directory.path().join("retry-after-started-at");

    let output = tool()
        .args(["ensure", "--build-dir"])
        .arg(directory.path())
        .args([
            "--version",
            VALID_VERSION,
            "--sha256",
            &digest(SYNTHETIC_AR),
        ])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &source)
        .env("SYNTHETIC_CURL_RETRY_AFTER", "2")
        .env("SYNTHETIC_CURL_ATTEMPT_MARKER", &attempts)
        .env("SYNTHETIC_CURL_RETRY_MARKER", &retry_marker)
        .output()
        .expect("run uyou-deb ensure");

    assert!(
        output.status.success(),
        "Retry-After response was not safely retried: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(attempts).unwrap(), "2");
    assert_eq!(
        fs::read(package_path(directory.path(), VALID_VERSION)).unwrap(),
        SYNTHETIC_AR
    );
}

#[test]
fn ensure_rejects_a_download_with_the_wrong_digest_and_leaves_no_file() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fictional-source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);
    let wrong_digest = digest(b"different fictional package bytes");

    let output = tool()
        .args(["ensure", "--build-dir"])
        .arg(directory.path())
        .args(["--version", VALID_VERSION, "--sha256", &wrong_digest])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &source)
        .output()
        .expect("run uyou-deb ensure");

    assert!(!output.status.success(), "accepted an unverified download");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("SHA-256 mismatch"),
        "wrong-digest download failed for an unexpected reason: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!package_path(directory.path(), VALID_VERSION).exists());
    assert_eq!(
        fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".download."))
            .count(),
        0,
        "temporary download file remained after digest rejection"
    );
}

#[test]
fn downloaded_synthetic_package_is_verified_promoted_and_extracted() {
    if !has_dpkg_deb() {
        eprintln!("skipping: dpkg-deb is not installed");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let archive = build_synthetic_deb(directory.path(), true);
    let build_dir = directory.path().join("Tweaks/uYou");
    fs::create_dir_all(&build_dir).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);
    let sha = digest(&fs::read(&archive).unwrap());

    let ensure = tool()
        .args(["ensure", "--build-dir"])
        .arg(&build_dir)
        .args(["--version", VALID_VERSION, "--sha256", &sha])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &archive)
        .output()
        .expect("run uyou-deb ensure");
    assert!(
        ensure.status.success(),
        "synthetic download rejected: {}",
        String::from_utf8_lossy(&ensure.stderr)
    );

    let extract = tool()
        .args(["extract", "--build-dir"])
        .arg(&build_dir)
        .args(["--version", VALID_VERSION, "--sha256", &sha])
        .output()
        .expect("run uyou-deb extract");

    assert!(
        extract.status.success(),
        "verified synthetic package did not extract: {}",
        String::from_utf8_lossy(&extract.stderr)
    );
    assert_eq!(
        fs::read(build_dir.join("Library/MobileSubstrate/DynamicLibraries/uYou.dylib")).unwrap(),
        b"NEW FICTIONAL DYLIB; NO PROPRIETARY MATERIAL"
    );
}

#[test]
fn ensure_failed_download_never_publishes_partial_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fictional-source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);
    let attempts = directory.path().join("curl-attempts");

    let output = tool()
        .args(["ensure", "--build-dir"])
        .arg(directory.path())
        .args([
            "--version",
            VALID_VERSION,
            "--sha256",
            &digest(SYNTHETIC_AR),
        ])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &source)
        .env("SYNTHETIC_CURL_FAILURE", "1")
        .env("SYNTHETIC_CURL_ATTEMPT_MARKER", &attempts)
        .output()
        .expect("run uyou-deb ensure");

    assert!(!output.status.success(), "failed transfer was accepted");
    assert_eq!(fs::read_to_string(attempts).unwrap(), "3");
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
fn ensure_does_not_clobber_a_competing_cache_entry() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fictional-source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    let competing = directory.path().join("competing.deb");
    fs::write(&competing, SYNTHETIC_AR).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);

    let output = tool()
        .args(["ensure", "--build-dir"])
        .arg(directory.path())
        .args([
            "--version",
            VALID_VERSION,
            "--sha256",
            &digest(SYNTHETIC_AR),
        ])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &source)
        .env("SYNTHETIC_CACHE_SOURCE", &competing)
        .env(
            "SYNTHETIC_CACHE_DESTINATION",
            package_path(directory.path(), VALID_VERSION),
        )
        .output()
        .expect("run uyou-deb ensure");

    assert!(
        output.status.success(),
        "valid competing cache was rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(package_path(directory.path(), VALID_VERSION)).unwrap(),
        SYNTHETIC_AR
    );
}

#[test]
fn ensure_rejects_an_invalid_version_without_creating_a_package_path() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fictional-source.deb");
    fs::write(&source, SYNTHETIC_AR).unwrap();
    let fake_bin = directory.path().join("fake-bin");
    compile_fake_curl(&fake_bin);
    let downloader_marker = directory.path().join("curl-was-invoked");
    let expression = "$(shell touch marker)";

    let output = tool()
        .args(["ensure", "--build-dir"])
        .arg(directory.path())
        .args(["--version", expression, "--sha256", &"a".repeat(64)])
        .env("PATH", path_with(&fake_bin))
        .env("SYNTHETIC_DEB", &source)
        .env("SYNTHETIC_CURL_MARKER", &downloader_marker)
        .output()
        .expect("run uyou-deb ensure");

    assert!(!output.status.success(), "unsafe version was accepted");
    assert!(
        !downloader_marker.exists(),
        "invalid version reached the downloader"
    );
    assert!(!package_path(directory.path(), expression).exists());
    assert_eq!(
        fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".download."))
            .count(),
        0,
        "invalid version created a temporary package path"
    );
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
        .args([
            "--version",
            VALID_VERSION,
            "--sha256",
            &digest(&fs::read(&package).unwrap()),
        ])
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
    assert!(library
        .join("Application Support/uYouBundle.bundle/Info.plist")
        .is_file());
    assert!(
        !stale_extra.exists(),
        "stale payload survived full replacement"
    );
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
        .args([
            "--version",
            VALID_VERSION,
            "--sha256",
            &digest(&fs::read(&package).unwrap()),
        ])
        .output()
        .expect("run uyou-deb extract");

    assert!(!output.status.success(), "incomplete archive was installed");
    assert_eq!(fs::read(old_dylib).unwrap(), old_bytes);
    assert!(library.is_dir());
}

#[test]
fn extract_fails_closed_when_the_cached_package_is_missing() {
    let directory = tempfile::tempdir().unwrap();

    let output = tool()
        .args(["extract", "--build-dir"])
        .arg(directory.path())
        .args(["--version", VALID_VERSION, "--sha256", &"a".repeat(64)])
        .output()
        .expect("run uyou-deb extract");

    assert!(
        !output.status.success(),
        "extraction succeeded without a package"
    );
}

#[test]
fn make_rejects_unvalidated_version_before_expanding_make_expressions() {
    let Some(make) = make_executable() else {
        eprintln!("skipping: GNU make is not installed");
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    prepare_make_checkout(directory.path());
    let marker = directory.path().join("make-version-expanded");
    let version = format!("$(shell touch {})", marker.display());
    let theos = directory.path().join("fake-theos");

    let output = Command::new(make)
        .args(["-f", "Makefile", "before-all"])
        .current_dir(directory.path())
        .env("UYOU_VERSION", version)
        .env("THEOS", &theos)
        .env("THEOS_MAKE_PATH", theos.join("makefiles"))
        .output()
        .expect("run GNU make");

    assert!(
        !output.status.success(),
        "unvalidated make invocation was accepted"
    );
    assert!(
        !marker.exists(),
        "GNU make expanded the unvalidated version"
    );
}

#[test]
fn make_uses_the_rust_tool_to_authenticate_and_extract_a_cached_package() {
    let (Some(make), true) = (make_executable(), has_dpkg_deb()) else {
        eprintln!("skipping: GNU make and dpkg-deb are required");
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    prepare_make_checkout(directory.path());
    let archive = build_synthetic_deb(directory.path(), true);
    let package = package_path(&directory.path().join("Tweaks/uYou"), VALID_VERSION);
    fs::copy(&archive, &package).unwrap();
    let package_sha = digest(&fs::read(&package).unwrap());
    let library = directory.path().join("Tweaks/uYou/Library");
    let old_dylib = library.join("MobileSubstrate/DynamicLibraries/uYou.dylib");
    fs::create_dir_all(old_dylib.parent().unwrap()).unwrap();
    fs::write(&old_dylib, b"OLD FICTIONAL DYLIB").unwrap();
    let stale_file = library.join("Stale.txt");
    fs::write(&stale_file, b"remove after full replacement").unwrap();
    let theos = directory.path().join("fake-theos");

    let output = Command::new(make)
        .args(["-f", "Makefile", "before-all"])
        .arg(format!("UYOU_DEB_COMMAND={}", tool_path().display()))
        .current_dir(directory.path())
        .env("UYOU_DEB_INPUTS_VALIDATED", "1")
        .env("UYOU_VERSION", VALID_VERSION)
        .env("UYOU_DEB_SHA256", package_sha)
        .env("THEOS", &theos)
        .env("THEOS_MAKE_PATH", theos.join("makefiles"))
        .output()
        .expect("run GNU make");

    assert!(
        output.status.success(),
        "Rust Makefile integration failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(library.join("MobileSubstrate/DynamicLibraries/uYou.dylib")).unwrap(),
        b"NEW FICTIONAL DYLIB; NO PROPRIETARY MATERIAL"
    );
    assert!(!stale_file.exists());
}

#[test]
fn jailbroken_make_path_needs_no_debian_digest_or_preflight_marker() {
    let Some(make) = make_executable() else {
        eprintln!("skipping: GNU make is not installed");
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    prepare_make_checkout(directory.path());
    let theos = directory.path().join("fake-theos");
    let staging = directory.path().join("staging");

    let output = Command::new(make)
        .args(["-f", "Makefile", "before-package", "JAILBROKEN=1"])
        .current_dir(directory.path())
        .env("THEOS", &theos)
        .env("THEOS_MAKE_PATH", theos.join("makefiles"))
        .env("THEOS_STAGING_DIR", &staging)
        .env_remove("UYOU_DEB_SHA256")
        .env_remove("UYOU_DEB_INPUTS_VALIDATED")
        .output()
        .expect("run GNU make");

    assert!(
        output.status.success(),
        "jailbroken Make path failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(staging
        .join("Library/Application Support/uYouPlus.bundle")
        .is_dir());
}

#[test]
fn workflow_runs_rust_preflight_before_marking_the_make_invocation_validated() {
    let workflow = fs::read_to_string(repo_root().join(".github/workflows/buildapp.yml")).unwrap();
    let preflight = workflow
        .find("cargo run --quiet --manifest-path rust/build-inputs/Cargo.toml --bin uyou-deb -- validate")
        .expect("workflow Rust preflight");
    let make = workflow
        .find("UYOU_DEB_INPUTS_VALIDATED=1 make package")
        .expect("workflow marked Make invocation");
    assert!(preflight < make, "Make is authorized before Rust preflight");
    assert!(workflow.contains("UYOU_DEB_SHA256: ${{ inputs.uyou_deb_sha256 }}"));
    assert!(workflow.contains("UYOU_VERSION: ${{ inputs.uyou_version }}"));
}
