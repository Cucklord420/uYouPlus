// IPA checksum and ZIP/plist verifier with isolated app-bundle preparation.
// The supplied IPA is preserved; archive contents are promoted only after verification.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

fn verified_archive(path: &Path, expected: &str) -> Result<(ZipArchive<File>, String), String> {
    let sha = Regex::new(r"(?i)^[0-9a-f]{64}$").unwrap();
    if !sha.is_match(expected) {
        return Err("Invalid SHA-256 digest".into());
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 4 * 1024 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if !format!("{:x}", hash.finalize()).eq_ignore_ascii_case(expected) {
        return Err("IPA checksum mismatch; refusing extraction".into());
    }
    file.rewind().map_err(|e| e.to_string())?;
    let mut archive = ZipArchive::new(file).map_err(|e| e.to_string())?;
    if archive.len() > 100_000 {
        return Err("Too many IPA archive entries".into());
    }
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut manifest_index = None;
    for index in 0..archive.len() {
        let member = archive.by_index(index).map_err(|e| e.to_string())?;
        let name = member.name().to_owned();
        let parts: Vec<&str> = name.split('/').collect();
        if name.is_empty()
            || name.starts_with('/')
            || name.contains('\\')
            || name.contains('\0')
            || parts[..parts.len().saturating_sub(1)]
                .iter()
                .any(|s| s.is_empty() || *s == "." || *s == "..")
            || parts.contains(&"..")
            || parts.first().is_some_and(|s| s.contains(':'))
        {
            return Err("Unsafe IPA archive entry path".into());
        }
        if member.enclosed_name().is_none() {
            return Err("Unsafe IPA archive entry path".into());
        }
        if member
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err("IPA contains a symbolic link".into());
        }
        if member.unix_mode().is_some_and(|mode| {
            let kind = mode & 0o170000;
            kind != 0 && kind != 0o100000 && kind != 0o040000
        }) {
            return Err("IPA contains a special file".into());
        }
        // The workflow only needs the app bundle. Permit two known historical
        // root metadata files but never arbitrary checkout-relative paths.
        let allowed = name == "Payload/"
            || name == "Payload/YouTube.app/"
            || name.starts_with("Payload/YouTube.app/")
            || (matches!(name.as_str(), "iTunesMetadata.plist" | "iTunesArtwork")
                && !member.is_dir());
        if !allowed {
            return Err("IPA contains an unapproved archive member".into());
        }
        let logical = name.trim_end_matches('/');
        if !seen.insert(logical.to_owned()) {
            return Err("Duplicate IPA archive entry".into());
        }
        total = total
            .checked_add(member.size())
            .ok_or("IPA decompressed size exceeds safety limit")?;
        if total > 8 * 1024 * 1024 * 1024 {
            return Err("IPA decompressed size exceeds safety limit".into());
        }
        if member.size() > 64 * 1024 * 1024 && member.compressed_size() == 0 {
            return Err("Suspicious archive compression ratio".into());
        }
        if member.compressed_size() != 0
            && (member.size() as u128) > (member.compressed_size() as u128) * 2000
        {
            return Err("Suspicious archive compression ratio".into());
        }
        if name == "Payload/YouTube.app/Info.plist" {
            manifest_index = Some(index);
        }
    }
    let index = manifest_index.ok_or("Not a YouTube IPA: missing Info.plist")?;
    let mut plist_file = archive.by_index(index).map_err(|e| e.to_string())?;
    // Bound manifest read to avoid allocating massive attacker-controlled XML/plist.
    let mut bytes = Vec::new();
    plist_file
        .by_ref()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("Info.plist exceeds safety limit".into());
    }
    let root = plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let version = root
        .as_dictionary()
        .and_then(|d| d.get("CFBundleVersion"))
        .and_then(plist::Value::as_string)
        .ok_or("Invalid YouTube CFBundleVersion")?;
    let pattern = Regex::new(r"^[0-9]+(\.[0-9]+){1,4}$").unwrap();
    if !pattern.is_match(version) {
        return Err("Invalid YouTube CFBundleVersion".into());
    }
    Ok((archive, version.to_owned()))
}

fn verify(path: &Path, expected: &str) -> Result<String, String> {
    verified_archive(path, expected).map(|(_, version)| version)
}

fn ensure_absent_output(path: &Path) -> Result<PathBuf, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(format!("destination already exists: {}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }

    let name = path
        .file_name()
        .ok_or("Output path must name a new directory")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
    Ok(parent.join(name))
}

fn checked_new_directory(path: &Path) -> Result<(), String> {
    fs::create_dir(path).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn set_archive_mode(path: &Path, mode: u32, directory: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    // Drop setuid/setgid/sticky bits and retain owner access for copying and cleanup.
    let owner_access = if directory { 0o700 } else { 0o600 };
    fs::set_permissions(
        path,
        fs::Permissions::from_mode((mode & 0o777) | owner_access),
    )
    .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn set_archive_mode(_path: &Path, _mode: u32, _directory: bool) -> Result<(), String> {
    Ok(())
}

fn extract_app_bundle<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    staging_dir: &Path,
) -> Result<(), String> {
    let mut directory_modes = Vec::new();

    for index in 0..archive.len() {
        let mut member = archive.by_index(index).map_err(|error| error.to_string())?;
        let name = member.name().to_owned();
        if matches!(name.as_str(), "iTunesMetadata.plist" | "iTunesArtwork") {
            continue;
        }
        if name == "Payload/" {
            let target = staging_dir.join("Payload");
            fs::create_dir_all(&target).map_err(|error| error.to_string())?;
            if let Some(mode) = member.unix_mode() {
                directory_modes.push((target, mode));
            }
            continue;
        }
        if !(name == "Payload/YouTube.app/" || name.starts_with("Payload/YouTube.app/")) {
            return Err("IPA contains an unapproved archive member".into());
        }

        let enclosed = member
            .enclosed_name()
            .ok_or("Unsafe IPA archive entry path")?;
        let target = staging_dir.join(enclosed);
        if member.is_dir() {
            fs::create_dir_all(&target).map_err(|error| error.to_string())?;
            if let Some(mode) = member.unix_mode() {
                directory_modes.push((target, mode));
            }
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(|error| error.to_string())?;
            io::copy(&mut member, &mut output).map_err(|error| error.to_string())?;
            output.flush().map_err(|error| error.to_string())?;
            if let Some(mode) = member.unix_mode() {
                set_archive_mode(&target, mode, false)?;
            }
        }
    }

    directory_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directory_modes {
        set_archive_mode(&path, mode, true)?;
    }
    Ok(())
}

fn copy_app_file(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("Staged IPA contains a non-regular app member".into());
    }
    let mut input = File::open(source).map_err(|error| error.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| error.to_string())?;
    io::copy(&mut input, &mut output).map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())?;
    fs::set_permissions(destination, metadata.permissions()).map_err(|error| error.to_string())
}

fn copy_app_directory(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() {
        return Err("Staged IPA app bundle is not a directory".into());
    }
    checked_new_directory(destination)?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let source_child = entry.path();
        let destination_child = destination.join(entry.file_name());
        let child_type = entry.file_type().map_err(|error| error.to_string())?;
        if child_type.is_dir() {
            copy_app_directory(&source_child, &destination_child)?;
        } else if child_type.is_file() {
            copy_app_file(&source_child, &destination_child)?;
        } else {
            return Err("Staged IPA contains a non-regular app member".into());
        }
    }
    fs::set_permissions(destination, metadata.permissions()).map_err(|error| error.to_string())
}

fn prepare(
    path: &Path,
    expected: &str,
    staging_dir: &Path,
    payload_destination: &Path,
) -> Result<String, String> {
    let staging = ensure_absent_output(staging_dir)?;
    let payload = ensure_absent_output(payload_destination)?;
    if staging.starts_with(&payload) || payload.starts_with(&staging) {
        return Err("Staging and payload destinations must not overlap".into());
    }

    let (mut archive, version) = verified_archive(path, expected)?;
    checked_new_directory(&staging)?;
    if let Err(error) = extract_app_bundle(&mut archive, &staging) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }

    let staged_app = staging.join("Payload/YouTube.app");
    if let Err(error) = checked_new_directory(&payload) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    if let Err(error) = copy_app_directory(&staged_app, &payload.join("YouTube.app")) {
        let _ = fs::remove_dir_all(&payload);
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    Ok(version)
}

fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("ipa") {
        eprintln!("Usage: ipa ipa --file PATH --sha256 HEX");
        std::process::exit(2);
    }
    let mut path = None;
    let mut sha = None;
    let mut staging_dir = None;
    let mut payload_destination = None;
    while let Some(flag) = args.next() {
        let Some(value) = args.next() else {
            eprintln!("Missing option value");
            std::process::exit(2);
        };
        match flag.as_str() {
            "--file" => path = Some(value),
            "--sha256" => sha = Some(value),
            "--staging-dir" => staging_dir = Some(value),
            "--payload-destination" => payload_destination = Some(value),
            _ => {
                eprintln!("Invalid option");
                std::process::exit(2);
            }
        }
    }
    let Some((path, sha)) = path.zip(sha) else {
        eprintln!("Missing required file or digest");
        std::process::exit(2);
    };
    let result = match (staging_dir, payload_destination) {
        (Some(staging), Some(payload)) => prepare(
            Path::new(&path),
            &sha,
            Path::new(&staging),
            Path::new(&payload),
        ),
        (None, None) => verify(Path::new(&path), &sha),
        _ => {
            eprintln!("Staging and payload destination must be supplied together");
            std::process::exit(2);
        }
    };
    match result {
        Ok(version) => println!("{version}"),
        Err(error) => {
            eprintln!("Build input rejected: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleVersion</key><string>19.25.4</string></dict></plist>"#;

    fn fixture(extra: &[(&str, &[u8])]) -> (tempfile::TempDir, String) {
        fixture_with_manifest(PLIST, extra)
    }

    fn fixture_with_manifest(
        manifest: &str,
        extra: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.ipa");
        let file = File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer
            .start_file("Payload/YouTube.app/Info.plist", options)
            .unwrap();
        writer.write_all(manifest.as_bytes()).unwrap();
        // zip 8 refuses duplicate names during writing. Build a distinct, same-length
        // fixture name and then restore the duplicate in both ZIP filename records.
        // This keeps the malformed-archive regression independent of ZipWriter policy.
        const NAME: &str = "Payload/YouTube.app/Info.plist";
        const ALIAS: &str = "Payload/YouTube.app/Info.plisX";
        let duplicate = extra.iter().filter(|(name, _)| *name == NAME).count();
        assert!(duplicate <= 1);
        for (name, data) in extra {
            let fixture_name = if *name == NAME { ALIAS } else { name };
            writer.start_file(fixture_name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        let mut contents = std::fs::read(&path).unwrap();
        if duplicate == 1 {
            let positions: Vec<usize> = contents
                .windows(ALIAS.len())
                .enumerate()
                .filter_map(|(position, bytes)| (bytes == ALIAS.as_bytes()).then_some(position))
                .collect();
            assert_eq!(
                positions.len(),
                2,
                "fixture ZIP local and central filenames"
            );
            for position in positions {
                contents[position..position + NAME.len()].copy_from_slice(NAME.as_bytes());
            }
            std::fs::write(&path, &contents).unwrap();
        }
        (directory, format!("{:x}", Sha256::digest(&contents)))
    }

    // ZipWriter's unix_permissions only stores rwx bits, so patch the central
    // directory host and mode bits for symlink, FIFO, and privileged-mode cases.
    fn fixture_with_unix_mode(name: &str, data: &[u8], mode: u32) -> (tempfile::TempDir, String) {
        let (directory, _) = fixture(&[(name, data)]);
        let path = directory.path().join("fixture.ipa");
        let mut contents = std::fs::read(&path).unwrap();
        let end = contents
            .windows(4)
            .rposition(|w| w == b"PK\x05\x06")
            .unwrap();
        let central_size =
            u32::from_le_bytes(contents[end + 12..end + 16].try_into().unwrap()) as usize;
        let mut offset =
            u32::from_le_bytes(contents[end + 16..end + 20].try_into().unwrap()) as usize;
        let central_end = offset + central_size;
        let mut patched = 0;
        while offset < central_end {
            assert_eq!(&contents[offset..offset + 4], b"PK\x01\x02");
            let name_len =
                u16::from_le_bytes(contents[offset + 28..offset + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(contents[offset + 30..offset + 32].try_into().unwrap()) as usize;
            let comment_len =
                u16::from_le_bytes(contents[offset + 32..offset + 34].try_into().unwrap()) as usize;
            let name_start = offset + 46;
            if &contents[name_start..name_start + name_len] == name.as_bytes() {
                contents[offset + 5] = 3; // Unix host system in "version made by".
                let external_attributes = mode << 16;
                contents[offset + 38..offset + 42]
                    .copy_from_slice(&external_attributes.to_le_bytes());
                patched += 1;
            }
            offset = name_start + name_len + extra_len + comment_len;
        }
        assert_eq!(offset, central_end);
        assert_eq!(patched, 1);
        std::fs::write(&path, &contents).unwrap();
        (directory, format!("{:x}", Sha256::digest(&contents)))
    }

    #[test]
    fn rejects_fifo_archive_members() {
        let (temp, sha) = fixture_with_unix_mode(
            "Payload/YouTube.app/pipe",
            b"synthetic fifo payload",
            0o010644,
        );
        let error = verify(&temp.path().join("fixture.ipa"), &sha).unwrap_err();
        assert!(error.contains("special file"), "{error}");
    }

    #[test]
    fn rejects_symbolic_link_archive_members() {
        let (temp, sha) = fixture_with_unix_mode(
            "Payload/YouTube.app/link",
            b"synthetic link target",
            0o120777,
        );
        let error = verify(&temp.path().join("fixture.ipa"), &sha).unwrap_err();
        assert!(error.contains("symbolic link"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_drops_privileged_mode_bits_and_keeps_executable_bits() {
        use std::os::unix::fs::PermissionsExt;

        let (temp, sha) = fixture_with_unix_mode(
            "Payload/YouTube.app/helper",
            b"synthetic executable",
            0o104755,
        );
        let ipa = temp.path().join("fixture.ipa");
        let staging = temp.path().join("staging");
        let payload = temp.path().join("checkout/main/Payload");
        std::fs::create_dir_all(payload.parent().unwrap()).unwrap();

        prepare(&ipa, &sha, &staging, &payload).unwrap();
        let mode = std::fs::metadata(payload.join("YouTube.app/helper"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "executable bits should be retained");
        assert_eq!(mode & 0o7000, 0, "privileged mode bits must be removed");
    }

    #[test]
    fn validates_synthetic_ipa_and_checksum() {
        let (temp, sha) = fixture(&[]);
        let path = temp.path().join("fixture.ipa");
        assert_eq!(verify(&path, &sha).unwrap(), "19.25.4");
        assert!(verify(&path, &"f".repeat(64)).is_err());
    }

    #[test]
    fn rejects_invalid_app_version() {
        let manifest = PLIST.replace("19.25.4", "$(bad)");
        let (temp, sha) = fixture_with_manifest(&manifest, &[]);
        let error = verify(&temp.path().join("fixture.ipa"), &sha).unwrap_err();
        assert!(error.contains("Invalid YouTube CFBundleVersion"), "{error}");
    }

    #[test]
    fn rejects_unsafe_paths_and_duplicates() {
        for name in [
            "../escape",
            "Payload/../escape",
            "Payload\\escape",
            "Payload/YouTube.app/Info.plist",
            "Payload/./bad",
            "/absolute/path",
        ] {
            let (temp, sha) = fixture(&[(name, b"bad")]);
            assert!(
                verify(&temp.path().join("fixture.ipa"), &sha).is_err(),
                "accepted {name}"
            );
        }
    }

    #[test]
    fn rejects_unexpected_ipa_roots_without_extracting() {
        for name in [
            "unexpected-file.txt",
            "Payload/Other.app/file",
            "Makefile",
            ".github/workflows/fake.yml",
            "iTunesMetadata.plist/extra",
        ] {
            let (temp, sha) = fixture(&[(name, b"synthetic-only")]);
            assert!(
                verify(&temp.path().join("fixture.ipa"), &sha).is_err(),
                "unexpected IPA entry accepted: {name}"
            );
        }
        for name in [
            "iTunesMetadata.plist",
            "iTunesArtwork",
            "Payload/YouTube.app/Assets.car",
        ] {
            let (temp, sha) = fixture(&[(name, b"synthetic-only")]);
            assert!(
                verify(&temp.path().join("fixture.ipa"), &sha).is_ok(),
                "approved IPA entry rejected: {name}"
            );
        }
    }

    #[test]
    fn rejects_not_a_zip_without_touching_original() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bad.ipa");
        std::fs::write(&file, b"not a zip").unwrap();
        let hash = format!("{:x}", Sha256::digest(b"not a zip"));
        assert!(verify(&file, &hash).is_err());
        assert_eq!(std::fs::read(file).unwrap(), b"not a zip");
    }
}
