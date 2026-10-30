// SPDX-License-Identifier: GPL-3.0-only
// Preserve the manual Theos build entry point while keeping artifact handling in Rust.

use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    time::{SystemTime, UNIX_EPOCH},
};
use uyouplus_inputs::archive::validate_local_ipa;

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

const BUILD_PROMPT: &str = "\x1b[34m==> \x1b[1;39mPath to the decrypted YouTube.ipa or YouTube.app. If nothing is provided, any ipa/app in the project's root directory will be used: ";
const MAX_LOCAL_IPA_BYTES: u64 = 4 * 1024 * 1024 * 1024;

struct StagingDirectory(PathBuf);

impl StagingDirectory {
    fn create(package_directory: &Path) -> Result<Self, String> {
        if !package_directory.exists() {
            fs::create_dir_all(package_directory).map_err(|error| {
                format!("Build output rejected: cannot create packages directory: {error}")
            })?;
        }

        let metadata = fs::symlink_metadata(package_directory).map_err(|error| {
            format!("Build output rejected: cannot inspect packages directory: {error}")
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("Build output rejected: packages must be a real directory".to_owned());
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for attempt in 0..1024u32 {
            let path = package_directory.join(format!(
                ".uyouplus-build-{}-{timestamp}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "Build output rejected: cannot create isolated package directory: {error}"
                    ));
                }
            }
        }

        Err("Build output rejected: cannot allocate a unique package directory".to_owned())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn run() -> Result<i32, String> {
    print!("{BUILD_PROMPT}");
    io::stdout()
        .flush()
        .map_err(|error| format!("Cannot display build prompt: {error}"))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("Cannot read build input: {error}"))?;
    let input = input.trim_end_matches(&['\r', '\n'][..]);
    let input_path = if input.is_empty() {
        #[cfg(unix)]
        {
            match discover_root_input() {
                Ok(path) => path,
                Err(_) => {
                    println!("❌ Error: Could not discover one root-level IPA/app candidate.");
                    return Ok(1);
                }
            }
        }
        #[cfg(not(unix))]
        {
            return Err(
                "Could not discover a root-level IPA/app candidate: unsupported build host"
                    .to_owned(),
            );
        }
    } else {
        PathBuf::from(input)
    };

    validate_local_input(&input_path)?;

    let package_directory = PathBuf::from("packages");
    let staging = StagingDirectory::create(&package_directory)?;
    let mut ipa_argument = OsString::from("IPA=");
    ipa_argument.push(input_path.as_os_str());
    let mut package_directory_argument = OsString::from("THEOS_PACKAGE_DIR=");
    package_directory_argument.push(staging.path().as_os_str());
    let status = match Command::new("make")
        .arg("package")
        .arg("THEOS_PACKAGE_SCHEME=rootless")
        .arg(ipa_argument)
        .arg("FINALPACKAGE=1")
        .arg(package_directory_argument)
        .env("THEOS_PACKAGE_DIR", staging.path())
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            println!("Failed building uYouPlus");
            return Err(format!("Cannot start make: {error}"));
        }
    };

    if !status.success() {
        println!("Failed building uYouPlus");
        return Ok(exit_code(status));
    }

    match publish_one_ipa(staging.path(), &package_directory) {
        Ok((path, digest)) => {
            println!("SHA256: {digest}  {}", path.display());
            open_output_directory(&package_directory);
            Ok(0)
        }
        Err(error) => {
            println!("Build output rejected: {error}");
            Ok(1)
        }
    }
}

fn validate_local_input(path: &Path) -> Result<(), String> {
    // Components omits trailing separators, so `link.app/` is checked with
    // lstat semantics on `link.app` instead of following the directory link.
    let checked_path = path
        .components()
        .fold(PathBuf::new(), |mut path, component| {
            path.push(component.as_os_str());
            path
        });
    let metadata = fs::symlink_metadata(&checked_path)
        .map_err(|error| format!("Build input rejected: cannot inspect input: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("Build input rejected: input cannot be a symbolic link".to_owned());
    }

    match checked_path
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some(extension) if extension.eq_ignore_ascii_case("ipa") => {
            if !metadata.is_file() {
                return Err("Build input rejected: IPA must be a regular file".to_owned());
            }
            if metadata.len() == 0 {
                return Err("Build input rejected: IPA cannot be empty".to_owned());
            }
            if metadata.len() > MAX_LOCAL_IPA_BYTES {
                return Err("Build input rejected: IPA exceeds the 4 GiB limit".to_owned());
            }
            validate_local_ipa(&checked_path)
                .map_err(|error| format!("Build input rejected: invalid IPA: {error}"))
        }
        Some(extension) if extension.eq_ignore_ascii_case("app") => {
            if !metadata.is_dir() {
                return Err("Build input rejected: .app input must be a directory".to_owned());
            }

            let info_plist = checked_path.join("Info.plist");
            let plist_metadata = fs::symlink_metadata(&info_plist).map_err(|error| {
                format!("Build input rejected: cannot inspect .app Info.plist: {error}")
            })?;
            if plist_metadata.file_type().is_symlink() || !plist_metadata.is_file() {
                return Err(
                    "Build input rejected: .app Info.plist must be a regular non-symlink file"
                        .to_owned(),
                );
            }
            if plist_metadata.len() == 0 {
                return Err("Build input rejected: .app Info.plist cannot be empty".to_owned());
            }

            // A user-selected .app is trusted after these boundary checks. Its
            // contents are not recursively authenticated or scanned here.
            Ok(())
        }
        _ => Err("Build input rejected: input must be a .ipa file or .app directory".to_owned()),
    }
}

#[cfg(unix)]
fn discover_root_input() -> Result<PathBuf, String> {
    if let Some(helper) = std::env::var_os("UYOUPLUS_INPUTS_BIN") {
        let output = Command::new(helper)
            .arg("discover-root-input")
            .output()
            .map_err(|error| format!("cannot start root input discovery helper: {error}"))?;
        if !output.status.success() {
            return Err("root input discovery helper failed".to_owned());
        }

        let mut path = output.stdout;
        if path.pop() != Some(0) || path.contains(&0) {
            return Err("root input discovery helper returned an invalid path".to_owned());
        }
        Ok(PathBuf::from(OsString::from_vec(path)))
    } else {
        crate::discovery::discover_current_directory_root_input()
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

fn publish_one_ipa(
    staging_directory: &Path,
    package_directory: &Path,
) -> Result<(PathBuf, String), String> {
    let mut artifacts = Vec::new();
    let entries = fs::read_dir(staging_directory)
        .map_err(|error| format!("cannot inspect staged package output: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot inspect staged output entry: {error}"))?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "ipa")
        {
            artifacts.push(entry.path());
        }
    }
    if artifacts.len() != 1 {
        return Err("expected exactly one IPA artifact in the fresh package directory".to_owned());
    }

    let staged_ipa = &artifacts[0];
    let metadata = fs::symlink_metadata(staged_ipa)
        .map_err(|error| format!("cannot inspect staged IPA: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err("IPA must be a nonempty regular file".to_owned());
    }
    let digest =
        sha256_file(staged_ipa).map_err(|error| format!("SHA-256 calculation failed: {error}"))?;
    let name = staged_ipa
        .file_name()
        .ok_or_else(|| "staged IPA has no filename".to_owned())?;

    for attempt in 0..1024u32 {
        let output_name = if attempt == 0 {
            name.to_os_string()
        } else {
            unique_output_name(name, attempt)
        };
        let output_path = package_directory.join(output_name);
        match fs::hard_link(staged_ipa, &output_path) {
            Ok(()) => return Ok((output_path, digest)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(link_error) => {
                match copy_publish_without_overwrite(staged_ipa, &output_path, &digest) {
                    Ok(()) => return Ok((output_path, digest)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(copy_error) => {
                        return Err(format!(
                            "cannot publish IPA without replacing existing output: hard link failed: {link_error}; no-overwrite copy failed: {copy_error}"
                        ));
                    }
                }
            }
        }
    }

    Err("cannot allocate a unique published IPA filename".to_owned())
}

fn copy_publish_without_overwrite(
    source_path: &Path,
    destination_path: &Path,
    expected_digest: &str,
) -> io::Result<()> {
    let mut source = File::open(source_path)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination_path)?;
    let copy_result = io::copy(&mut source, &mut destination).and_then(|_| destination.sync_all());
    drop(destination);
    if let Err(error) = copy_result {
        return Err(cleanup_partial_output(destination_path, error));
    }

    match sha256_file(destination_path) {
        Ok(digest) if digest == expected_digest => Ok(()),
        Ok(_) => Err(cleanup_partial_output(
            destination_path,
            io::Error::new(io::ErrorKind::InvalidData, "copied IPA digest mismatch"),
        )),
        Err(error) => Err(cleanup_partial_output(destination_path, error)),
    }
}

fn cleanup_partial_output(path: &Path, error: io::Error) -> io::Error {
    match fs::remove_file(path) {
        Ok(()) => error,
        Err(cleanup_error) if cleanup_error.kind() == io::ErrorKind::NotFound => error,
        Err(cleanup_error) => io::Error::new(
            error.kind(),
            format!(
                "{error}; cannot remove partial published IPA {}: {cleanup_error}",
                path.display()
            ),
        ),
    }
}

fn unique_output_name(name: &std::ffi::OsStr, attempt: u32) -> OsString {
    let path = Path::new(name);
    let mut output = path.file_stem().unwrap_or(name).to_os_string();
    output.push(format!("-build-{}-{attempt}", std::process::id()));
    if let Some(extension) = path.extension() {
        output.push(".");
        output.push(extension);
    }
    output
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(target_os = "macos")]
fn open_output_directory(package_directory: &Path) {
    use std::process::Stdio;
    let _ = Command::new("open")
        .arg(package_directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(target_os = "macos"))]
fn open_output_directory(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_publication_copies_to_a_new_path() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("staged.ipa");
        let destination = temp.path().join("published.ipa");
        fs::write(&source, b"synthetic IPA bytes").unwrap();
        let expected_digest = sha256_file(&source).unwrap();

        copy_publish_without_overwrite(&source, &destination, &expected_digest).unwrap();

        assert_eq!(fs::read(destination).unwrap(), b"synthetic IPA bytes");
    }

    #[test]
    fn fallback_publication_never_replaces_an_existing_path() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("staged.ipa");
        let destination = temp.path().join("published.ipa");
        fs::write(&source, b"new synthetic IPA bytes").unwrap();
        fs::write(&destination, b"existing output").unwrap();
        let expected_digest = sha256_file(&source).unwrap();

        let error =
            copy_publish_without_overwrite(&source, &destination, &expected_digest).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(destination).unwrap(), b"existing output");
    }
}
