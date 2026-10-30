// IPA checksum and ZIP/plist verifier with isolated app-bundle preparation.
// The supplied IPA is preserved; archive contents are promoted only after verification.

#[cfg(target_os = "macos")]
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use uyouplus_inputs::{
    archive::{rounded_allocation, verified_archive, AppFootprint},
    validate_ipa_url,
};
use zip::ZipArchive;

const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;
const MAX_IPA_DOWNLOAD_BYTES: u64 = 4 * BYTES_PER_GIB;
const DISK_RESERVE_BYTES: u64 = 4 * BYTES_PER_GIB;
const DOWNLOAD_ATTEMPTS: usize = 3;
fn verify(path: &Path, expected: &str) -> Result<String, String> {
    verified_archive(path, Some(expected)).map(|(_, version, _)| version)
}

#[derive(Debug)]
enum StreamError {
    LimitExceeded,
    Io,
    OutputOpen,
    CleanupFailed,
}

fn transfer_limit_for_free_space(free_bytes: u64) -> Result<u64, String> {
    let available_above_reserve = free_bytes.saturating_sub(DISK_RESERVE_BYTES);
    if available_above_reserve == 0 {
        return Err("Insufficient free space for the IPA download reserve".into());
    }
    Ok(available_above_reserve.min(MAX_IPA_DOWNLOAD_BYTES))
}

fn copy_stream_with_limit<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64, StreamError> {
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        // Read at most one byte beyond the remaining allowance so an oversized
        // stream is detected without ever writing its overflow byte.
        let remaining = limit - copied;
        let read_limit = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
        let count = match reader.read(&mut buffer[..read_limit]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(StreamError::Io),
            Ok(count) => count,
        };
        if count == 0 {
            return Ok(copied);
        }
        let writable = remaining.min(count as u64) as usize;
        writer
            .write_all(&buffer[..writable])
            .map_err(|_| StreamError::Io)?;
        if count as u64 > remaining {
            return Err(StreamError::LimitExceeded);
        }
        copied += count as u64;
    }
}

fn cleanup_download_partial(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Unable to remove a partial IPA download".into()),
    }
}

fn write_stream_to_new_file<R: Read>(
    path: &Path,
    mut reader: R,
    limit: u64,
) -> Result<u64, StreamError> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| StreamError::OutputOpen)?;
    let result = copy_stream_with_limit(&mut reader, &mut output, limit).and_then(|copied| {
        output.flush().map_err(|_| StreamError::Io)?;
        Ok(copied)
    });
    if result.is_err() {
        drop(output);
        if cleanup_download_partial(path).is_err() {
            return Err(StreamError::CleanupFailed);
        }
    }
    result
}

fn validate_download_url(value: &str) -> Result<(), String> {
    validate_ipa_url(value).map_err(str::to_owned)
}

fn ensure_absent_file(path: &Path) -> Result<PathBuf, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err("IPA download destination already exists".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("Unable to inspect IPA download destination".into()),
    }
    let name = path
        .file_name()
        .ok_or("IPA download path must name a file")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent =
        fs::canonicalize(parent).map_err(|_| "Unable to inspect IPA download directory")?;
    Ok(parent.join(name))
}

fn curl_command(url_environment: &str) -> Command {
    // Read the URL from a private config pipe instead of exposing it in argv.
    let mut command = Command::new("curl");
    command
        .args([
            "--disable",
            "--fail",
            "--location",
            "--silent",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "600",
            "--output",
            "-",
            "--config",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove(url_environment);
    command
}

fn curl_config_line(url: &str) -> String {
    let escaped = url.replace('\\', "\\\\").replace('"', "\\\"");
    format!("url = \"{escaped}\"\n")
}

enum AttemptFailure {
    TooLarge,
    Retryable,
    Fatal(String),
}

fn curl_attempt(
    url: &str,
    url_environment: &str,
    path: &Path,
    limit: u64,
) -> Result<(), AttemptFailure> {
    let mut child = match curl_command(url_environment).spawn() {
        Ok(child) => child,
        Err(_) => {
            return Err(AttemptFailure::Fatal(
                "Unable to start the HTTPS download client".into(),
            ));
        }
    };
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(AttemptFailure::Fatal(
            "HTTPS download client did not accept its configuration".into(),
        ));
    };
    if stdin.write_all(curl_config_line(url).as_bytes()).is_err() {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err(AttemptFailure::Fatal(
            "Unable to configure the HTTPS download client".into(),
        ));
    }
    drop(stdin);
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(AttemptFailure::Fatal(
            "HTTPS download client did not provide a stream".into(),
        ));
    };

    let streamed = write_stream_to_new_file(path, stdout, limit);
    if let Err(error) = streamed {
        let _ = child.kill();
        let _ = child.wait();
        return match error {
            StreamError::LimitExceeded => Err(AttemptFailure::TooLarge),
            StreamError::Io => Err(AttemptFailure::Retryable),
            StreamError::OutputOpen => Err(AttemptFailure::Fatal(
                "Unable to create IPA download file".into(),
            )),
            StreamError::CleanupFailed => Err(AttemptFailure::Fatal(
                "Unable to remove a partial IPA download".into(),
            )),
        };
    }

    match child.wait() {
        Ok(status) if status.success() => Ok(()),
        _ => {
            if cleanup_download_partial(path).is_err() {
                return Err(AttemptFailure::Fatal(
                    "Unable to remove a partial IPA download".into(),
                ));
            }
            Err(AttemptFailure::Retryable)
        }
    }
}

fn retry_download<T, F, B>(mut attempt: F, mut backoff: B) -> Result<T, String>
where
    F: FnMut() -> Result<T, AttemptFailure>,
    B: FnMut(usize),
{
    for attempt_number in 0..DOWNLOAD_ATTEMPTS {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(AttemptFailure::Fatal(error)) => return Err(error),
            Err(AttemptFailure::TooLarge) => {
                return Err("IPA download exceeded the available byte limit".into());
            }
            Err(AttemptFailure::Retryable) if attempt_number + 1 < DOWNLOAD_ATTEMPTS => {
                backoff(attempt_number);
            }
            Err(AttemptFailure::Retryable) => {}
        }
    }
    Err("IPA download failed after two retries".into())
}

fn download_ipa(url: &str, url_environment: &str, path: &Path) -> Result<(), String> {
    validate_download_url(url)?;
    let destination = ensure_absent_file(path)?;
    let parent = destination
        .parent()
        .ok_or("IPA download path must name a file")?;

    retry_download(
        || {
            let disk_space = filesystem_space(parent).map_err(AttemptFailure::Fatal)?;
            let limit = transfer_limit_for_free_space(disk_space.free_bytes)
                .map_err(AttemptFailure::Fatal)?;
            curl_attempt(url, url_environment, &destination, limit)
        },
        |attempt| thread::sleep(Duration::from_secs(attempt as u64 + 1)),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpacePool {
    may_be_shared: bool,
    // Native APFS container BSD disk number; valid for this short-lived process.
    // None for an APFS pool whose container identity could not be established.
    container: Option<u64>,
}

impl SpacePool {
    fn independent() -> Self {
        Self {
            may_be_shared: false,
            container: None,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn apfs_pool_from_info(bytes: &[u8]) -> SpacePool {
    let container = plist::Value::from_reader(io::Cursor::new(bytes))
        .ok()
        .and_then(|info| {
            let reference = info
                .as_dictionary()?
                .get("APFSContainerReference")?
                .as_string()?;
            let number = reference.strip_prefix("disk")?;
            if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            number.parse().ok()
        });
    SpacePool {
        may_be_shared: true,
        container,
    }
}

#[cfg(target_os = "macos")]
fn filesystem_pool(path: &std::ffi::CStr, volume: u64) -> Result<SpacePool, String> {
    use std::os::unix::ffi::OsStrExt;
    use std::sync::{Mutex, OnceLock};

    // Cache only identity, never free bytes. Live statvfs queries still run for
    // every checked write; diskutil is not invoked for each stream chunk.
    static POOLS: OnceLock<Mutex<HashMap<u64, SpacePool>>> = OnceLock::new();
    let mut pools = POOLS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "Unable to inspect filesystem space-pool identity")?;
    if let Some(pool) = pools.get(&volume) {
        return Ok(*pool);
    }
    let mut native = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: path is NUL-terminated and native points to writable statfs storage.
    if unsafe { libc::statfs(path.as_ptr(), native.as_mut_ptr()) } != 0 {
        return Err("Unable to inspect filesystem space-pool identity".into());
    }
    // SAFETY: successful statfs initialized native.
    let native = unsafe { native.assume_init() };
    let fs_type: Vec<u8> = native
        .f_fstypename
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    let pool = if fs_type == b"apfs" {
        let mount: Vec<u8> = native
            .f_mntonname
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        Command::new("/usr/sbin/diskutil")
            .args(["info", "-plist"])
            .arg(std::ffi::OsStr::from_bytes(&mount))
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| apfs_pool_from_info(&output.stdout))
            .unwrap_or(SpacePool {
                may_be_shared: true,
                container: None,
            })
    } else {
        SpacePool::independent()
    };
    pools.insert(volume, pool);
    Ok(pool)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn filesystem_pool(_path: &std::ffi::CStr, _volume: u64) -> Result<SpacePool, String> {
    Ok(SpacePool::independent())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DiskSpace {
    volume: u64,
    free_bytes: u64,
    allocation_unit: u64,
    pool: SpacePool,
}

#[cfg(unix)]
fn filesystem_space(path: &Path) -> Result<DiskSpace, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path).map_err(|_| "Unable to inspect available disk space")?;
    if !metadata.is_dir() {
        return Err("Disk-space query path is not a directory".into());
    }
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "Invalid path for disk-space query")?;
    let mut native = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is NUL-terminated and `native` points to writable storage
    // for the platform's `statvfs` result structure.
    let result = unsafe { libc::statvfs(c_path.as_ptr(), native.as_mut_ptr()) };
    if result != 0 {
        return Err("Unable to inspect available disk space".into());
    }
    // SAFETY: a successful `statvfs` call initialized the result structure.
    let native = unsafe { native.assume_init() };
    let block_size = if native.f_frsize == 0 {
        native.f_bsize as u128
    } else {
        native.f_frsize as u128
    };
    let free_bytes = ((native.f_bavail as u128) * block_size).min(u64::MAX as u128) as u64;
    if block_size == 0 || block_size > u64::MAX as u128 {
        return Err("Invalid filesystem allocation unit".into());
    }
    Ok(DiskSpace {
        volume: metadata.dev(),
        free_bytes,
        allocation_unit: block_size as u64,
        pool: filesystem_pool(&c_path, metadata.dev())?,
    })
}

#[cfg(not(unix))]
fn filesystem_space(_path: &Path) -> Result<DiskSpace, String> {
    Err("Disk-space preflight is supported only on macOS and Linux".into())
}

fn ensure_preflight_space(
    footprint: &AppFootprint,
    staging: DiskSpace,
    payload: DiskSpace,
) -> Result<(), String> {
    let staging_estimate = footprint.allocation_estimate(staging.allocation_unit)?;
    let payload_estimate = footprint.allocation_estimate(payload.allocation_unit)?;
    let shared_pool = staging.pool.may_be_shared
        && payload.pool.may_be_shared
        && match (staging.pool.container, payload.pool.container) {
            (Some(first), Some(second)) => first == second,
            // Unknown APFS identities may share a container. Combining estimates
            // is the safe fallback; distinct known containers remain independent.
            _ => true,
        };
    if staging.volume == payload.volume || shared_pool {
        let both_copies_with_reserve = staging_estimate
            .checked_add(payload_estimate)
            .and_then(|size| size.checked_add(DISK_RESERVE_BYTES))
            .ok_or("IPA extraction space requirement overflow")?;
        if staging.free_bytes.min(payload.free_bytes) < both_copies_with_reserve {
            return Err("Insufficient free space for IPA extraction and promotion".into());
        }
    } else if staging.free_bytes.saturating_sub(DISK_RESERVE_BYTES) < staging_estimate
        || payload.free_bytes.saturating_sub(DISK_RESERVE_BYTES) < payload_estimate
    {
        return Err("Insufficient free space for IPA extraction and promotion".into());
    }
    Ok(())
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

fn check_live_reserve<F>(
    path: &Path,
    pending_bytes: u64,
    space_for_path: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Path) -> Result<DiskSpace, String>,
{
    let space = space_for_path(path)?;
    let pending = rounded_allocation(pending_bytes, space.allocation_unit)?
        .checked_add(
            space
                .allocation_unit
                .checked_mul(2)
                .ok_or("IPA allocation estimate overflow")?,
        )
        .and_then(|size| size.checked_add(DISK_RESERVE_BYTES))
        .ok_or("IPA allocation estimate overflow")?;
    if space.free_bytes < pending {
        return Err("Insufficient live free space to retain the IPA reserve".into());
    }
    Ok(())
}

struct ReserveWriter<'a, W, F> {
    output: W,
    directory: &'a Path,
    space_for_path: &'a mut F,
}

impl<W: Write, F: FnMut(&Path) -> Result<DiskSpace, String>> Write for ReserveWriter<'_, W, F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        check_live_reserve(self.directory, bytes.len() as u64, self.space_for_path)
            .map_err(io::Error::other)?;
        self.output.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()?;
        check_live_reserve(self.directory, 0, self.space_for_path).map_err(io::Error::other)
    }
}

fn checked_new_directory<F>(path: &Path, space_for_path: &mut F) -> Result<(), String>
where
    F: FnMut(&Path) -> Result<DiskSpace, String>,
{
    let parent = path.parent().ok_or("New directory must have a parent")?;
    check_live_reserve(parent, 0, space_for_path)?;
    fs::create_dir(path).map_err(|error| error.to_string())
}

fn create_app_directories<F>(path: &Path, space_for_path: &mut F) -> Result<(), String>
where
    F: FnMut(&Path) -> Result<DiskSpace, String>,
{
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => return Ok(()),
        Ok(_) => return Err("App directory path is not a regular directory".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    create_app_directories(
        path.parent().ok_or("App directory must have a parent")?,
        space_for_path,
    )?;
    checked_new_directory(path, space_for_path)
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

fn extract_app_bundle<R: Read + Seek, F: FnMut(&Path) -> Result<DiskSpace, String>>(
    archive: &mut ZipArchive<R>,
    staging_dir: &Path,
    max_app_bundle_size: u64,
    space_for_path: &mut F,
) -> Result<(), String> {
    let mut directory_modes = Vec::new();
    let mut extracted_bytes = 0u64;

    for index in 0..archive.len() {
        let mut member = archive.by_index(index).map_err(|error| error.to_string())?;
        let name = member.name().to_owned();
        if matches!(name.as_str(), "iTunesMetadata.plist" | "iTunesArtwork") {
            continue;
        }
        if name == "Payload/" {
            let target = staging_dir.join("Payload");
            create_app_directories(&target, space_for_path)?;
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
            create_app_directories(&target, space_for_path)?;
            if let Some(mode) = member.unix_mode() {
                directory_modes.push((target, mode));
            }
        } else {
            if let Some(parent) = target.parent() {
                create_app_directories(parent, space_for_path)?;
            }
            let parent = target.parent().ok_or("App file must have a parent")?;
            check_live_reserve(parent, 0, space_for_path)?;
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(|error| error.to_string())?;
            let mut output = ReserveWriter {
                output: file,
                directory: parent,
                space_for_path,
            };
            let expected_size = member.size();
            let remaining = max_app_bundle_size
                .checked_sub(extracted_bytes)
                .ok_or("IPA expanded beyond its declared app size")?;
            let copied =
                copy_stream_with_limit(&mut member, &mut output, remaining).map_err(|error| {
                    match error {
                        StreamError::LimitExceeded => {
                            "IPA expanded beyond its declared app size".to_owned()
                        }
                        StreamError::Io | StreamError::OutputOpen | StreamError::CleanupFailed => {
                            "Unable to extract IPA app member".to_owned()
                        }
                    }
                })?;
            if copied != expected_size {
                return Err("IPA app member size did not match its declaration".into());
            }
            extracted_bytes = extracted_bytes
                .checked_add(copied)
                .ok_or("IPA decompressed size exceeds safety limit")?;
            output.flush().map_err(|error| error.to_string())?;
            drop(output);
            if let Some(mode) = member.unix_mode() {
                set_archive_mode(&target, mode, false)?;
            }
        }
    }

    if extracted_bytes != max_app_bundle_size {
        return Err("IPA app bundle size did not match its declaration".into());
    }

    directory_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directory_modes {
        check_live_reserve(staging_dir, 0, space_for_path)?;
        set_archive_mode(&path, mode, true)?;
    }
    check_live_reserve(staging_dir, 0, space_for_path)
}

fn copy_app_file<F: FnMut(&Path) -> Result<DiskSpace, String>>(
    source: &Path,
    destination: &Path,
    space_for_path: &mut F,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("Staged IPA contains a non-regular app member".into());
    }
    let mut input = File::open(source).map_err(|error| error.to_string())?;
    let parent = destination.parent().ok_or("App file must have a parent")?;
    check_live_reserve(parent, 0, space_for_path)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| error.to_string())?;
    let mut output = ReserveWriter {
        output: file,
        directory: parent,
        space_for_path,
    };
    let copied = copy_stream_with_limit(&mut input, &mut output, metadata.len())
        .map_err(|_| "Unable to promote IPA app member while retaining the disk reserve")?;
    if copied != metadata.len() {
        return Err("Staged IPA app member changed size".into());
    }
    output.flush().map_err(|error| error.to_string())?;
    drop(output);
    fs::set_permissions(destination, metadata.permissions()).map_err(|error| error.to_string())
}

fn copy_app_directory<F: FnMut(&Path) -> Result<DiskSpace, String>>(
    source: &Path,
    destination: &Path,
    space_for_path: &mut F,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() {
        return Err("Staged IPA app bundle is not a directory".into());
    }
    checked_new_directory(destination, space_for_path)?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let source_child = entry.path();
        let destination_child = destination.join(entry.file_name());
        let child_type = entry.file_type().map_err(|error| error.to_string())?;
        if child_type.is_dir() {
            copy_app_directory(&source_child, &destination_child, space_for_path)?;
        } else if child_type.is_file() {
            copy_app_file(&source_child, &destination_child, space_for_path)?;
        } else {
            return Err("Staged IPA contains a non-regular app member".into());
        }
    }
    check_live_reserve(destination, 0, space_for_path)?;
    fs::set_permissions(destination, metadata.permissions()).map_err(|error| error.to_string())?;
    check_live_reserve(destination, 0, space_for_path)
}

fn prepare(
    path: &Path,
    expected: &str,
    staging_dir: &Path,
    payload_destination: &Path,
) -> Result<String, String> {
    prepare_with_space_provider(
        path,
        expected,
        staging_dir,
        payload_destination,
        filesystem_space,
    )
}

fn prepare_with_space_provider<F>(
    path: &Path,
    expected: &str,
    staging_dir: &Path,
    payload_destination: &Path,
    mut space_for_path: F,
) -> Result<String, String>
where
    F: FnMut(&Path) -> Result<DiskSpace, String>,
{
    let staging = ensure_absent_output(staging_dir)?;
    let payload = ensure_absent_output(payload_destination)?;
    if staging.starts_with(&payload) || payload.starts_with(&staging) {
        return Err("Staging and payload destinations must not overlap".into());
    }

    let (mut archive, version, footprint) = verified_archive(path, Some(expected))?;
    let staging_parent = staging
        .parent()
        .ok_or("Staging destination must have an existing parent")?;
    let payload_parent = payload
        .parent()
        .ok_or("Payload destination must have an existing parent")?;
    let staging_space = space_for_path(staging_parent)?;
    let payload_space = space_for_path(payload_parent)?;
    ensure_preflight_space(&footprint, staging_space, payload_space)?;

    checked_new_directory(&staging, &mut space_for_path)?;
    if let Err(error) = extract_app_bundle(
        &mut archive,
        &staging,
        footprint.logical_bytes,
        &mut space_for_path,
    ) {
        return Err(cleanup_owned_outputs(error, &[&staging]));
    }

    let staged_app = staging.join("Payload/YouTube.app");
    if let Err(error) = checked_new_directory(&payload, &mut space_for_path) {
        return Err(cleanup_owned_outputs(error, &[&staging]));
    }
    let promoted = copy_app_directory(
        &staged_app,
        &payload.join("YouTube.app"),
        &mut space_for_path,
    )
    .and_then(|_| check_live_reserve(staging_parent, 0, &mut space_for_path))
    .and_then(|_| check_live_reserve(payload_parent, 0, &mut space_for_path));
    if let Err(error) = promoted {
        return Err(cleanup_owned_outputs(error, &[&payload, &staging]));
    }
    Ok(version)
}

fn cleanup_owned_outputs(mut error: String, paths: &[&Path]) -> String {
    for path in paths {
        if let Err(cleanup) = fs::remove_dir_all(path) {
            if cleanup.kind() != io::ErrorKind::NotFound {
                error.push_str(&format!(
                    "; cleanup failed for {}: {cleanup} (owned output may remain)",
                    path.display()
                ));
            }
        }
    }
    error
}

fn download_cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut args = args;
    let mut url_environment = None;
    let mut output = None;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| "Missing download option value".to_owned())?;
        match flag.as_str() {
            "--url-env" => url_environment = Some(value),
            "--output" => output = Some(value),
            _ => return Err("Invalid download option".into()),
        }
    }
    let url_environment = url_environment.ok_or("Missing URL environment variable name")?;
    let url = std::env::var(&url_environment).map_err(|_| "Missing IPA download URL")?;
    let output = output.ok_or("Missing IPA download output path")?;
    download_ipa(&url, &url_environment, Path::new(&output))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    if command.as_deref() == Some("download") {
        if let Err(error) = download_cli(args) {
            eprintln!("IPA download failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if command.as_deref() != Some("ipa") {
        eprintln!(
            "Usage: ipa ipa --file PATH --sha256 HEX | ipa download --url-env NAME --output PATH"
        );
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
    use sha2::{Digest, Sha256};
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
    fn accepts_explicit_directories_and_their_children() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.ipa");
        let file = File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.add_directory("Payload/", options).unwrap();
        writer
            .add_directory("Payload/YouTube.app/", options)
            .unwrap();
        writer
            .start_file("Payload/YouTube.app/Info.plist", options)
            .unwrap();
        writer.write_all(PLIST.as_bytes()).unwrap();
        writer.finish().unwrap();
        let contents = std::fs::read(&path).unwrap();
        let sha = format!("{:x}", Sha256::digest(&contents));

        assert_eq!(verify(&path, &sha).unwrap(), "19.25.4");
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
    fn rejects_filesystem_equivalent_archive_paths() {
        type CollisionCase<'a> = (&'a str, &'a [(&'a str, &'a [u8])]);

        let cases: &[CollisionCase<'_>] = &[
            (
                "Info.plist case alias",
                &[("Payload/YouTube.app/info.plist", b"alternate plist")],
            ),
            (
                "directory case alias",
                &[
                    ("Payload/YouTube.app/Assets/first.bin", b"first"),
                    ("Payload/YouTube.app/assets/second.bin", b"second"),
                ],
            ),
            (
                "canonical Unicode normalization alias",
                &[
                    ("Payload/YouTube.app/caf\u{e9}.bin", b"composed"),
                    ("Payload/YouTube.app/cafe\u{301}.bin", b"decomposed"),
                ],
            ),
            (
                "full Unicode case-fold alias",
                &[
                    ("Payload/YouTube.app/stra\u{df}e.bin", b"sharp s"),
                    ("Payload/YouTube.app/STRASSE.bin", b"expanded fold"),
                ],
            ),
            (
                "file used as a directory",
                &[
                    ("Payload/YouTube.app/Cache", b"file"),
                    ("Payload/YouTube.app/Cache/child", b"child"),
                ],
            ),
            (
                "case-folded file and directory alias",
                &[
                    ("Payload/YouTube.app/Assets.car", b"file"),
                    ("Payload/YouTube.app/assets.car/child", b"child"),
                ],
            ),
        ];

        for (description, extra) in cases {
            let (temp, sha) = fixture(extra);
            let error = verify(&temp.path().join("fixture.ipa"), &sha).unwrap_err();
            assert!(
                error.contains("collision"),
                "{description} was not rejected as a path collision: {error}"
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

    #[test]
    fn transfer_limit_reserves_space_and_never_exceeds_the_hard_cap() {
        assert!(transfer_limit_for_free_space(DISK_RESERVE_BYTES - 1).is_err());
        assert!(transfer_limit_for_free_space(DISK_RESERVE_BYTES).is_err());
        assert_eq!(
            transfer_limit_for_free_space(DISK_RESERVE_BYTES + 2 * 1024 * 1024).unwrap(),
            2 * 1024 * 1024
        );
        assert_eq!(
            transfer_limit_for_free_space(DISK_RESERVE_BYTES + MAX_IPA_DOWNLOAD_BYTES * 2).unwrap(),
            MAX_IPA_DOWNLOAD_BYTES
        );
    }

    #[test]
    fn bounded_stream_accepts_exact_limit_and_never_writes_overflow_byte() {
        let mut exact = Vec::new();
        let mut exact_reader = &b"four"[..];
        assert_eq!(
            copy_stream_with_limit(&mut exact_reader, &mut exact, 4).unwrap(),
            4
        );
        assert_eq!(exact, b"four");

        let mut too_large = Vec::new();
        let mut too_large_reader = &b"fives"[..];
        assert!(copy_stream_with_limit(&mut too_large_reader, &mut too_large, 4).is_err());
        assert_eq!(too_large, b"five");
    }

    #[test]
    fn failed_stream_removes_its_partial_download() {
        struct FailingReader(bool);
        impl Read for FailingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("synthetic transfer failure"));
                }
                self.0 = true;
                buffer[..3].copy_from_slice(b"ipa");
                Ok(3)
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let partial = temp.path().join("partial.ipa");
        assert!(write_stream_to_new_file(&partial, FailingReader(false), 8).is_err());
        assert!(
            !partial.exists(),
            "failed transfers must not leave partials"
        );

        let oversized = temp.path().join("oversized.ipa");
        assert!(write_stream_to_new_file(&oversized, &b"oversized"[..], 4).is_err());
        assert!(!oversized.exists(), "over-limit transfers must be removed");
    }

    #[test]
    fn download_url_requires_https() {
        assert!(validate_download_url("http://example.com/app.ipa").is_err());
        assert!(validate_download_url("https://example.com/app.ipa").is_ok());
    }

    #[test]
    fn curl_protocol_timeout_and_stdout_options_are_preserved() {
        let command = curl_command("YOUTUBE_URL");
        let args: Vec<String> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.first().map(String::as_str), Some("--disable"));
        let proto = args
            .iter()
            .position(|argument| argument == "--proto")
            .unwrap();
        let redirect = args
            .iter()
            .position(|argument| argument == "--proto-redir")
            .unwrap();
        let timeout = args
            .iter()
            .position(|argument| argument == "--max-time")
            .unwrap();
        let output = args
            .iter()
            .position(|argument| argument == "--output")
            .unwrap();
        assert_eq!(args[proto + 1], "=https");
        assert_eq!(args[redirect + 1], "=https");
        assert_eq!(args[timeout + 1], "600");
        assert_eq!(args[output + 1], "-");
        assert!(!args.iter().any(|argument| argument == "--url"));
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "--config" && pair[1] == "-"));
        assert!(command.get_envs().any(|(name, value)| {
            name == std::ffi::OsStr::new("YOUTUBE_URL") && value.is_none()
        }));
    }

    #[test]
    fn downloader_makes_two_retries_after_the_first_attempt() {
        let mut attempts = 0;
        let mut backoffs = 0;
        let result = retry_download(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(AttemptFailure::Retryable)
                } else {
                    Ok("downloaded")
                }
            },
            |_| backoffs += 1,
        );
        assert_eq!(result.unwrap(), "downloaded");
        assert_eq!(attempts, 3);
        assert_eq!(backoffs, 2);
    }

    #[test]
    fn extraction_preflight_accounts_for_both_copies_and_reserve() {
        let app_size = AppFootprint {
            logical_bytes: 1024,
            file_sizes: vec![1024],
            directories: 2,
        };
        // Each copy: 3 directory-data + 4 object-metadata + 1 file-data blocks.
        let same_volume_required = 65_536 + DISK_RESERVE_BYTES;
        assert!(ensure_preflight_space(
            &app_size,
            DiskSpace {
                volume: 7,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: same_volume_required
            },
            DiskSpace {
                volume: 7,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: same_volume_required
            },
        )
        .is_ok());
        assert!(ensure_preflight_space(
            &app_size,
            DiskSpace {
                volume: 7,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: same_volume_required - 1
            },
            DiskSpace {
                volume: 7,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: same_volume_required - 1
            },
        )
        .is_err());

        let separate_volume_required = 32_768 + DISK_RESERVE_BYTES;
        assert!(ensure_preflight_space(
            &app_size,
            DiskSpace {
                volume: 7,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: separate_volume_required
            },
            DiskSpace {
                volume: 9,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: separate_volume_required
            },
        )
        .is_ok());
        assert!(ensure_preflight_space(
            &app_size,
            DiskSpace {
                volume: 7,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: separate_volume_required
            },
            DiskSpace {
                volume: 9,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: separate_volume_required - 1
            },
        )
        .is_err());
    }

    #[test]
    fn allocation_preflight_rejects_tiny_files_with_many_implicit_directories() {
        // 7,801 files, 975,002 directories and 998,403 indexed components;
        // all paths fit the existing depth/count limits. Do not extract this tree.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("directory-heavy.ipa");
        let mut writer = ZipWriter::new(File::create(&path).unwrap());
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer
            .start_file("Payload/YouTube.app/Info.plist", options)
            .unwrap();
        writer.write_all(PLIST.as_bytes()).unwrap();
        let nested = "d/".repeat(124);
        for branch in 0..7_800 {
            writer
                .start_file(
                    format!("Payload/YouTube.app/b{branch:04}/{nested}f"),
                    options,
                )
                .unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
        let sha = format!("{:x}", Sha256::digest(fs::read(&path).unwrap()));
        let (_, _, app_size) = verified_archive(&path, Some(&sha)).unwrap();
        assert_eq!(app_size.directories, 975_002);
        assert_eq!(app_size.file_sizes.len(), 7_801);
        let space = DiskSpace {
            volume: 7,
            pool: SpacePool::independent(),
            allocation_unit: 4096,
            free_bytes: 5 * BYTES_PER_GIB,
        };
        assert!(
            ensure_preflight_space(&app_size, space, space).is_err(),
            "tiny logical size must not hide the allocation of nearly a million directories"
        );
    }

    #[test]
    fn allocation_preflight_rounds_small_files_before_reserving_both_copies() {
        let (temp, sha) = fixture(&[("Payload/YouTube.app/second", b"x")]);
        let (_, _, app_size) =
            verified_archive(&temp.path().join("fixture.ipa"), Some(&sha)).unwrap();
        let space = DiskSpace {
            volume: 7,
            pool: SpacePool::independent(),
            allocation_unit: 4096,
            free_bytes: DISK_RESERVE_BYTES + 4096,
        };
        assert!(
            ensure_preflight_space(&app_size, space, space).is_err(),
            "four tiny file copies need more than one allocation block"
        );
    }

    #[test]
    fn low_space_during_directory_creation_cleans_owned_outputs() {
        let (temp, sha) = fixture(&[]);
        let staging = temp.path().join("staging");
        let payload = temp.path().join("Payload");
        let result = prepare_with_space_provider(
            &temp.path().join("fixture.ipa"),
            &sha,
            &staging,
            &payload,
            |_| {
                Ok(DiskSpace {
                    volume: 7,
                    pool: SpacePool::independent(),
                    allocation_unit: 4096,
                    free_bytes: if staging.exists() {
                        DISK_RESERVE_BYTES
                    } else {
                        100 * BYTES_PER_GIB
                    },
                })
            },
        );
        assert!(
            result.is_err(),
            "space must be checked again after staging is created"
        );
        assert!(!staging.exists());
        assert!(!payload.exists());
    }

    #[test]
    fn low_space_during_promotion_cleans_both_owned_outputs() {
        let (temp, sha) = fixture(&[]);
        let staging = temp.path().join("staging");
        let payload = temp.path().join("Payload");
        let result = prepare_with_space_provider(
            &temp.path().join("fixture.ipa"),
            &sha,
            &staging,
            &payload,
            |_| {
                Ok(DiskSpace {
                    volume: 7,
                    pool: SpacePool::independent(),
                    allocation_unit: 4096,
                    free_bytes: if payload.exists() {
                        DISK_RESERVE_BYTES
                    } else {
                        100 * BYTES_PER_GIB
                    },
                })
            },
        );
        assert!(
            result.is_err(),
            "promotion must not rely on the earlier space snapshot"
        );
        assert!(!staging.exists());
        assert!(!payload.exists());
    }

    #[test]
    fn low_space_during_a_file_stream_stops_and_cleans_extraction() {
        let contents = vec![b'x'; 192 * 1024];
        let (temp, sha) = fixture(&[("Payload/YouTube.app/data", &contents)]);
        let staging = temp.path().join("staging");
        let payload = temp.path().join("Payload");
        let streamed_file = staging.join("Payload/YouTube.app/data");
        let result = prepare_with_space_provider(
            &temp.path().join("fixture.ipa"),
            &sha,
            &staging,
            &payload,
            |_| {
                let pressure =
                    fs::metadata(&streamed_file).is_ok_and(|metadata| metadata.len() >= 64 * 1024);
                Ok(DiskSpace {
                    volume: 7,
                    pool: SpacePool::independent(),
                    allocation_unit: 4096,
                    free_bytes: if pressure {
                        DISK_RESERVE_BYTES
                    } else {
                        100 * BYTES_PER_GIB
                    },
                })
            },
        );
        assert!(
            result.is_err(),
            "a file stream must recheck the live reserve between chunks"
        );
        assert!(!staging.exists());
        assert!(!payload.exists());
    }

    #[test]
    fn allocation_preflight_uses_each_destination_allocation_unit() {
        let footprint = AppFootprint {
            logical_bytes: 1,
            file_sizes: vec![1],
            directories: 2,
        };
        let staging = DiskSpace {
            volume: 7,
            pool: SpacePool::independent(),
            free_bytes: DISK_RESERVE_BYTES + 32_768,
            allocation_unit: 4096,
        };
        let payload = DiskSpace {
            volume: 9,
            pool: SpacePool::independent(),
            free_bytes: DISK_RESERVE_BYTES + 65_536,
            allocation_unit: 8192,
        };
        assert!(ensure_preflight_space(&footprint, staging, payload).is_ok());
        assert!(ensure_preflight_space(
            &footprint,
            staging,
            DiskSpace {
                free_bytes: payload.free_bytes - 1,
                ..payload
            }
        )
        .is_err());
        assert!(ensure_preflight_space(
            &footprint,
            DiskSpace {
                allocation_unit: 8192,
                ..staging
            },
            payload
        )
        .is_err());
        assert!(ensure_preflight_space(
            &footprint,
            DiskSpace {
                allocation_unit: 0,
                ..staging
            },
            payload
        )
        .is_err());
        assert!(footprint.allocation_estimate(u64::MAX).is_err());
    }

    #[test]
    fn allocation_estimate_counts_explicit_and_shared_directories_once() {
        let (temp, _) = fixture(&[
            ("Payload/YouTube.app/Assets/a", b"x"),
            ("Payload/YouTube.app/Assets/b", b"x"),
        ]);
        let path = temp.path().join("fixture.ipa");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut writer = ZipWriter::new_append(file).unwrap();
        writer
            .add_directory("Payload/YouTube.app/Assets/", SimpleFileOptions::default())
            .unwrap();
        writer.finish().unwrap();
        let sha = format!("{:x}", Sha256::digest(fs::read(&path).unwrap()));
        let (_, _, footprint) = verified_archive(&path, Some(&sha)).unwrap();
        assert_eq!(footprint.directories, 3);
        assert_eq!(footprint.file_sizes.len(), 3);
        // 4 directory-data + 7 object-metadata + 3 file-data blocks.
        assert_eq!(footprint.allocation_estimate(4096).unwrap(), 57_344);
    }

    #[test]
    fn shared_apfs_pool_is_budgeted_once_across_distinct_volumes() {
        // These two volume IDs refer to one APFS container with 5.5 GiB free.
        // Either copy fits separately; both copies plus the reserve do not.
        let footprint = AppFootprint {
            logical_bytes: BYTES_PER_GIB,
            file_sizes: vec![BYTES_PER_GIB],
            directories: 2,
        };
        let staging = DiskSpace {
            volume: 7,
            pool: SpacePool {
                may_be_shared: true,
                container: Some(17),
            },
            free_bytes: 11 * BYTES_PER_GIB / 2,
            allocation_unit: 4096,
        };
        let payload = DiskSpace {
            volume: 9,
            ..staging
        };
        assert!(
            ensure_preflight_space(&footprint, staging, payload).is_err(),
            "different APFS volume IDs must not double-count one shared free-space pool"
        );
        let independent_payload = DiskSpace {
            pool: SpacePool {
                container: Some(18),
                ..staging.pool
            },
            ..payload
        };
        assert!(
            ensure_preflight_space(&footprint, staging, independent_payload).is_ok(),
            "different identified containers can each fit one copy"
        );
        let unknown_payload = DiskSpace {
            pool: SpacePool {
                container: None,
                ..staging.pool
            },
            ..payload
        };
        assert!(
            ensure_preflight_space(&footprint, staging, unknown_payload).is_err(),
            "unidentified APFS pools need conservative combined budgeting"
        );
    }

    #[test]
    fn native_apfs_identity_parser_rejects_missing_or_malformed_container_references() {
        let known = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>APFSContainerReference</key><string>disk17</string></dict></plist>"#;
        assert_eq!(
            apfs_pool_from_info(known),
            SpacePool {
                may_be_shared: true,
                container: Some(17)
            }
        );
        for bytes in [b"not a plist".as_slice(), br#"<?xml version="1.0"?><plist version="1.0"><dict/></plist>"#,
            br#"<?xml version="1.0"?><plist version="1.0"><dict><key>APFSContainerReference</key><string>disk17s1</string></dict></plist>"#] {
            assert_eq!(apfs_pool_from_info(bytes), SpacePool { may_be_shared: true, container: None });
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn records_native_macos_space_pool_detection() {
        let temp = tempfile::tempdir().unwrap();
        let space = filesystem_space(temp.path()).unwrap();
        println!("macOS native free-space pool: {:?}", space.pool);
        assert!(space.allocation_unit > 0);
    }

    #[test]
    fn cleanup_reports_each_failed_path_and_keeps_the_original_error() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let absent = temp.path().join("absent");
        // remove_dir_all must refuse regular files; both failures must be reported.
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let error =
            cleanup_owned_outputs("original build failure".into(), &[&first, &second, &absent]);
        assert!(error.starts_with("original build failure"));
        assert_eq!(error.matches("cleanup failed").count(), 2);
        assert!(error.contains(&first.display().to_string()));
        assert!(error.contains(&second.display().to_string()));
        assert!(!error.contains(&absent.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn extraction_error_reports_owned_staging_cleanup_failure() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, sha) = fixture(&[]);
        let staging = temp.path().join("staging");
        let payload = temp.path().join("Payload");
        let result = prepare_with_space_provider(
            &temp.path().join("fixture.ipa"),
            &sha,
            &staging,
            &payload,
            |_| {
                if staging.exists() {
                    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o500)).unwrap();
                    return Err("synthetic reserve failure".into());
                }
                Ok(DiskSpace {
                    volume: 7,
                    pool: SpacePool::independent(),
                    free_bytes: 100 * BYTES_PER_GIB,
                    allocation_unit: 4096,
                })
            },
        );
        // Restore permissions before assertions so the fixture can clean itself up.
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            staging.exists(),
            "the fixture must leave actual cleanup residue"
        );
        let error = result.unwrap_err();
        assert!(error.contains("synthetic reserve failure"), "{error}");
        assert!(
            error.contains("cleanup failed"),
            "the cleanup failure was hidden: {error}"
        );
        assert!(
            error.contains(&staging.display().to_string()),
            "residue path missing: {error}"
        );
    }

    #[test]
    fn insufficient_space_fails_before_creating_staging_or_payload() {
        let (temp, sha) = fixture(&[("Payload/YouTube.app/file", b"synthetic app data")]);
        let ipa = temp.path().join("fixture.ipa");
        let staging = temp.path().join("runner-temp/extracted");
        let payload = temp.path().join("checkout/Payload");
        fs::create_dir_all(staging.parent().unwrap()).unwrap();
        fs::create_dir_all(payload.parent().unwrap()).unwrap();

        let result = prepare_with_space_provider(&ipa, &sha, &staging, &payload, |_| {
            Ok(DiskSpace {
                volume: 1,
                pool: SpacePool::independent(),
                allocation_unit: 4096,
                free_bytes: DISK_RESERVE_BYTES,
            })
        });
        assert!(result.is_err());
        assert!(!staging.exists());
        assert!(!payload.exists());
    }
}
