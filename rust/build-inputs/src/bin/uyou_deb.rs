// SPDX-License-Identifier: GPL-3.0-only
// Authenticate and safely extract the externally sourced uYou Debian package.

use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CURL_ERROR_BYTES: u64 = 64 * 1024;
const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const RELEASE_BASE: &str = "https://repo.miro92.com/debs/com.miro.uyou_";
const PACKAGE_SUFFIX: &str = "_iphoneos-arm.deb";
static UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

type Result<T> = std::result::Result<T, String>;

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("A reviewed 64-character uYou package SHA-256 is required".into());
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if !(1..=40).contains(&bytes.len())
        || !bytes.first().is_some_and(|byte| byte.is_ascii_digit())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'+' | b'-')
        })
    {
        return Err("uYou package version must be 1-40 safe ASCII characters beginning with a digit".into());
    }
    Ok(())
}

fn validate_inputs(version: &str, digest: &str) -> Result<()> {
    validate_digest(digest)?;
    validate_version(version)
}

fn package_path(build_dir: &Path, version: &str) -> PathBuf {
    build_dir.join(format!("com.miro.uyou_{version}{PACKAGE_SUFFIX}"))
}

fn require_real_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("build directory is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("uYou build directory must be a real directory, not a symlink".into());
    }
    Ok(())
}

fn verify_package(expected_sha256: &str, path: &Path) -> Result<()> {
    validate_digest(expected_sha256)?;
    let parent = path
        .parent()
        .ok_or_else(|| "uYou package path has no parent directory".to_string())?;
    require_real_directory(parent)?;

    let before_open = fs::symlink_metadata(path)
        .map_err(|error| format!("uYou package is unavailable: {error}"))?;
    if before_open.file_type().is_symlink() || !before_open.is_file() {
        return Err("uYou package must be a regular file, not a symlink or directory".into());
    }
    if before_open.len() < AR_MAGIC.len() as u64 {
        return Err("uYou package must be a nonempty Debian ar archive".into());
    }
    if before_open.len() > MAX_PACKAGE_BYTES {
        return Err("uYou package exceeds the 512 MiB size limit".into());
    }

    let mut file = File::open(path).map_err(|error| format!("cannot read uYou package: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| format!("cannot inspect uYou package: {error}"))?
        .is_file()
    {
        return Err("uYou package is not a regular file".into());
    }

    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|error| format!("cannot read Debian archive header: {error}"))?;
    if &magic != AR_MAGIC {
        return Err("uYou download is not a Debian ar archive".into());
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind uYou package: {error}"))?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash uYou package: {error}"))?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| "uYou package exceeds the 512 MiB size limit".to_string())?;
        if size > MAX_PACKAGE_BYTES {
            return Err("uYou package exceeds the 512 MiB size limit".into());
        }
        hasher.update(&buffer[..count]);
    }

    let actual = format!("{:x}", hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err("uYou package SHA-256 mismatch; refusing extraction".into());
    }
    Ok(())
}

trait Downloader {
    fn download(&self, url: &str, destination: &mut File) -> Result<()>;
}

struct CurlDownloader;

impl Downloader for CurlDownloader {
    fn download(&self, url: &str, destination: &mut File) -> Result<()> {
        let mut command = Command::new("curl");
        command
            .args([
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-redirs",
                "5",
                "--connect-timeout",
                "30",
                "--max-time",
                "600",
                "--max-filesize",
                "536870912",
                "--retry",
                "2",
                "--output",
                "-",
            ])
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot start HTTPS package download: {error}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "cannot read HTTPS package download".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "cannot read HTTPS download diagnostics".to_string())?;
        let stderr_reader = thread::spawn(move || {
            let mut limited = stderr.take(MAX_CURL_ERROR_BYTES + 1);
            let mut bytes = Vec::new();
            let _ = limited.read_to_end(&mut bytes);
            bytes.truncate(MAX_CURL_ERROR_BYTES as usize);
            bytes
        });

        let mut limited = stdout.take(MAX_PACKAGE_BYTES + 1);
        let copied = match io::copy(&mut limited, destination) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stderr_reader.join();
                return Err(format!("cannot save downloaded uYou package: {error}"));
            }
        };
        drop(limited);
        if copied > MAX_PACKAGE_BYTES {
            let _ = child.kill();
        }
        let status = child
            .wait()
            .map_err(|error| format!("cannot wait for HTTPS package download: {error}"))?;
        let stderr = stderr_reader.join().unwrap_or_default();
        if copied > MAX_PACKAGE_BYTES {
            return Err("uYou package exceeds the 512 MiB size limit".into());
        }
        if !status.success() {
            let detail = String::from_utf8_lossy(&stderr);
            return Err(if detail.trim().is_empty() {
                format!("HTTPS package download failed with {status}")
            } else {
                format!("HTTPS package download failed: {}", detail.trim())
            });
        }
        Ok(())
    }
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct TemporaryDirectory {
    path: PathBuf,
    remove_on_drop: bool,
}

impl TemporaryDirectory {
    fn preserve(&mut self) {
        self.remove_on_drop = false;
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn create_temporary_file(directory: &Path, destination: &Path) -> Result<(TemporaryFile, File)> {
    let name = destination
        .file_name()
        .ok_or_else(|| "uYou package path has no file name".to_string())?
        .to_string_lossy();
    for _ in 0..128 {
        let id = UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("{name}.download.{}.{}", process::id(), id));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((TemporaryFile(path), file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot create temporary package file: {error}")),
        }
    }
    Err("cannot allocate a unique temporary package file".into())
}

fn ensure_package_with<D: Downloader>(
    build_dir: &Path,
    version: &str,
    expected_sha256: &str,
    downloader: &D,
) -> Result<PathBuf> {
    validate_inputs(version, expected_sha256)?;
    require_real_directory(build_dir)?;
    let package = package_path(build_dir, version);

    match fs::symlink_metadata(&package) {
        Ok(_) => {
            verify_package(expected_sha256, &package)?;
            return Ok(package);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect cached uYou package: {error}")),
    }

    let url = format!("{RELEASE_BASE}{version}{PACKAGE_SUFFIX}");
    let (temporary, mut file) = create_temporary_file(build_dir, &package)?;
    downloader.download(&url, &mut file)?;
    file.flush()
        .map_err(|error| format!("cannot flush downloaded uYou package: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync downloaded uYou package: {error}"))?;
    drop(file);
    verify_package(expected_sha256, &temporary.0)?;

    match fs::hard_link(&temporary.0, &package) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // Another process may have published the cache during this download.
            // Accept it only if its bytes independently match the reviewed digest.
            verify_package(expected_sha256, &package)?;
        }
        Err(error) => return Err(format!("cannot publish verified uYou package: {error}")),
    }
    drop(temporary);
    Ok(package)
}

fn ensure_package(build_dir: &Path, version: &str, expected_sha256: &str) -> Result<PathBuf> {
    ensure_package_with(build_dir, version, expected_sha256, &CurlDownloader)
}

fn require_directory(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| format!("required uYou package directory is missing: {description}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("required uYou package path is not a real directory: {description}"));
    }
    Ok(())
}

fn require_regular_file(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| format!("required uYou package file is missing: {description}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("required uYou package path is not a regular file: {description}"));
    }
    Ok(())
}

fn validate_payload(library: &Path) -> Result<()> {
    require_directory(library, "Library")?;
    require_directory(&library.join("MobileSubstrate"), "MobileSubstrate")?;
    require_directory(
        &library.join("MobileSubstrate/DynamicLibraries"),
        "DynamicLibraries",
    )?;
    require_regular_file(
        &library.join("MobileSubstrate/DynamicLibraries/uYou.dylib"),
        "uYou.dylib",
    )?;
    require_directory(&library.join("Application Support"), "Application Support")?;
    require_directory(
        &library.join("Application Support/uYouBundle.bundle"),
        "uYouBundle.bundle",
    )?;
    Ok(())
}

fn create_temporary_directory(parent: &Path, prefix: &str) -> Result<TemporaryDirectory> {
    for _ in 0..128 {
        let id = UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("{prefix}{}.{}", process::id(), id));
        match fs::create_dir(&path) {
            Ok(()) => {
                return Ok(TemporaryDirectory {
                    path,
                    remove_on_drop: true,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot create staging directory: {error}")),
        }
    }
    Err("cannot allocate a unique staging directory".into())
}

fn promote_library_with<F>(
    staged_library: &Path,
    build_dir: &Path,
    rename: &mut F,
) -> Result<()>
where
    F: FnMut(&Path, &Path) -> io::Result<()>,
{
    validate_payload(staged_library)?;
    let installed = build_dir.join("Library");
    let previous = match fs::symlink_metadata(&installed) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("existing uYou Library must be a real directory".into());
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("cannot inspect existing uYou Library: {error}")),
    };

    let mut backup_directory = if previous {
        Some(create_temporary_directory(build_dir, ".uyou-library-backup-")?)
    } else {
        None
    };
    let backup = backup_directory
        .as_ref()
        .map(|directory| directory.path.join("Library"));
    if let Some(backup_path) = backup.as_ref() {
        rename(&installed, backup_path)
            .map_err(|error| format!("cannot back up existing uYou Library: {error}"))?;
    }

    if let Err(install_error) = rename(staged_library, &installed) {
        if let Some(backup_path) = backup.as_ref() {
            if let Err(restore_error) = rename(backup_path, &installed) {
                if let Some(directory) = backup_directory.as_mut() {
                    directory.preserve();
                }
                return Err(format!(
                    "new uYou payload could not be installed and the old payload could not be restored; old Library remains at {} ({restore_error})",
                    backup_path.display()
                ));
            }
        }
        return Err(format!("cannot install new uYou Library: {install_error}"));
    }

    if let Some(directory) = backup_directory {
        fs::remove_dir_all(&directory.path).map_err(|error| {
            format!(
                "new uYou Library was installed but the old backup remains at {}: {error}",
                directory.path.display()
            )
        })?;
    }
    Ok(())
}

fn extract_package(build_dir: &Path, version: &str, expected_sha256: &str) -> Result<()> {
    validate_inputs(version, expected_sha256)?;
    require_real_directory(build_dir)?;
    let package = package_path(build_dir, version);
    verify_package(expected_sha256, &package)?;

    let stage = create_temporary_directory(build_dir, ".uyou-deb-stage-")?;
    let output = Command::new("dpkg-deb")
        .args(["--extract"])
        .arg(&package)
        .arg(&stage.path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("dpkg-deb is required to extract uYou: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "dpkg-deb could not extract the verified package (exit status {})",
            output.status
        ));
    }

    let staged_library = stage.path.join("Library");
    validate_payload(&staged_library)?;
    promote_library_with(&staged_library, build_dir, &mut |from, to| fs::rename(from, to))
}

fn read_option(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_operation_args(
    mut args: impl Iterator<Item = String>,
) -> Result<(PathBuf, String, String)> {
    let mut build_dir = None;
    let mut version = None;
    let mut digest = None;
    while let Some(flag) = args.next() {
        let value = read_option(&mut args, &flag)?;
        let slot = match flag.as_str() {
            "--build-dir" => &mut build_dir,
            "--version" => &mut version,
            "--sha256" => &mut digest,
            _ => return Err(format!("unknown option: {flag}")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("duplicate option: {flag}"));
        }
    }
    Ok((
        PathBuf::from(build_dir.ok_or_else(|| "missing --build-dir".to_string())?),
        version.ok_or_else(|| "missing --version".to_string())?,
        digest.ok_or_else(|| "missing --sha256".to_string())?,
    ))
}

fn validate_environment() -> Result<()> {
    let version = env::var("UYOU_VERSION")
        .map_err(|_| "UYOU_VERSION is required for uYou package validation".to_string())?;
    let digest = env::var("UYOU_DEB_SHA256")
        .map_err(|_| "UYOU_DEB_SHA256 is required for uYou package validation".to_string())?;
    validate_inputs(&version, &digest)
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let operation = args
        .next()
        .ok_or_else(|| "usage: uyou-deb <validate|ensure|extract> [options]".to_string())?;
    match operation.as_str() {
        "validate" => {
            if args.next().is_some() {
                return Err("validate does not accept command-line options".into());
            }
            validate_environment()?;
            println!("uYou package inputs validated");
            Ok(())
        }
        "ensure" | "extract" => {
            let (build_dir, version, digest) = parse_operation_args(args)?;
            validate_inputs(&version, &digest)?;
            if operation == "ensure" {
                ensure_package(&build_dir, &version, &digest)?;
                println!("uYou Debian package verified");
            } else {
                extract_package(&build_dir, &version, &digest)?;
                println!("uYou Debian payload extracted");
            }
            Ok(())
        }
        _ => Err("usage: uyou-deb <validate|ensure|extract> [options]".into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("uYou package rejected: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_failure_restores_the_previous_library() {
        let temp = tempfile::tempdir().unwrap();
        let build_dir = temp.path();
        let old_dylib = build_dir.join("Library/MobileSubstrate/DynamicLibraries/uYou.dylib");
        fs::create_dir_all(old_dylib.parent().unwrap()).unwrap();
        fs::write(&old_dylib, b"OLD FICTIONAL DYLIB").unwrap();
        let old_bundle = build_dir.join("Library/Application Support/uYouBundle.bundle");
        fs::create_dir_all(&old_bundle).unwrap();

        let staged_library = build_dir.join("stage/Library");
        let staged_dylib = staged_library.join("MobileSubstrate/DynamicLibraries/uYou.dylib");
        fs::create_dir_all(staged_dylib.parent().unwrap()).unwrap();
        fs::write(&staged_dylib, b"NEW FICTIONAL DYLIB").unwrap();
        let staged_bundle = staged_library.join("Application Support/uYouBundle.bundle");
        fs::create_dir_all(&staged_bundle).unwrap();

        let mut fail_install = true;
        let result = promote_library_with(&staged_library, build_dir, &mut |from, to| {
            if from == staged_library.as_path() && fail_install {
                fail_install = false;
                return Err(io::Error::other("injected promotion failure"));
            }
            fs::rename(from, to)
        });

        assert!(result.is_err());
        assert_eq!(fs::read(old_dylib).unwrap(), b"OLD FICTIONAL DYLIB");
        assert!(old_bundle.is_dir());
    }
}
