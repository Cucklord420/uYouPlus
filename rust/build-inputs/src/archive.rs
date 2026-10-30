// SPDX-License-Identifier: GPL-3.0-only
// Shared IPA archive verification for workflow preparation and local builds.

use caseless::Caseless;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek},
    path::Path,
};
use unicode_normalization::UnicodeNormalization;
use zip::ZipArchive;

const ARCHIVE_PATH_COLLISION: &str = "IPA archive path collision or file/directory conflict";
const MAX_ARCHIVE_PATH_COMPONENTS_PER_ENTRY: usize = 128;
const MAX_ARCHIVE_PATH_COMPONENTS: usize = 1_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArchivePathKind {
    Directory,
    File,
}

struct ArchivePathNode {
    spelling: String,
    kind: ArchivePathKind,
    explicit: bool,
    children: HashMap<String, ArchivePathNode>,
}

impl ArchivePathNode {
    fn root() -> Self {
        Self {
            spelling: String::new(),
            kind: ArchivePathKind::Directory,
            explicit: false,
            children: HashMap::new(),
        }
    }
}

fn canonical_path_component(component: &str) -> String {
    // Unicode canonical caseless matching is NFD, full default case folding, then NFD.
    component.nfd().default_case_fold().nfd().collect()
}

#[derive(Debug)]
pub struct AppFootprint {
    pub logical_bytes: u64,
    pub file_sizes: Vec<u64>,
    // Includes the Payload wrapper, but excludes the fresh outer output directory.
    pub directories: u64,
}

fn archive_directory_count(node: &ArchivePathNode) -> u64 {
    node.children
        .values()
        .filter(|child| child.kind == ArchivePathKind::Directory)
        .map(|child| 1 + archive_directory_count(child))
        .sum()
}

fn rounded_allocation(bytes: u64, unit: u64) -> Result<u64, String> {
    if unit == 0 {
        return Err("Invalid filesystem allocation unit".into());
    }
    bytes
        .checked_add(unit - 1)
        .map(|size| size / unit)
        .and_then(|blocks| blocks.checked_mul(unit))
        .ok_or_else(|| "IPA allocation estimate overflow".into())
}

impl AppFootprint {
    pub fn allocation_estimate(&self, unit: u64) -> Result<u64, String> {
        // Budget rounded file data, a directory-data block per unique directory,
        // and one metadata block per file/directory. Include the fresh output root.
        // Counting Payload for both copies deliberately overestimates promotion.
        // This is conservative headroom, not an exact APFS metadata bound.
        let object_blocks = self
            .directories
            .checked_add(1)
            .and_then(|directories| directories.checked_mul(2))
            .and_then(|blocks| blocks.checked_add(self.file_sizes.len() as u64))
            .and_then(|blocks| blocks.checked_mul(unit))
            .ok_or("IPA allocation estimate overflow")?;
        self.file_sizes
            .iter()
            .try_fold(object_blocks, |total, size| {
                total
                    .checked_add(rounded_allocation(*size, unit)?)
                    .ok_or_else(|| "IPA allocation estimate overflow".into())
            })
    }
}

fn register_archive_path(
    root: &mut ArchivePathNode,
    name: &str,
    is_directory: bool,
    indexed_components: &mut usize,
) -> Result<(), String> {
    let logical = name.trim_end_matches('/');
    let mut components = logical.split('/').peekable();
    let mut node = root;
    let mut components_in_entry = 0;

    while let Some(component) = components.next() {
        components_in_entry += 1;
        if components_in_entry > MAX_ARCHIVE_PATH_COMPONENTS_PER_ENTRY {
            return Err("IPA archive entry has too many path components".into());
        }
        *indexed_components = (*indexed_components)
            .checked_add(1)
            .ok_or("IPA archive has too many path components")?;
        if *indexed_components > MAX_ARCHIVE_PATH_COMPONENTS {
            return Err("IPA archive has too many path components".into());
        }

        let is_final = components.peek().is_none();
        let folded = canonical_path_component(component);
        let child = node
            .children
            .entry(folded)
            .or_insert_with(|| ArchivePathNode {
                spelling: component.to_owned(),
                kind: ArchivePathKind::Directory,
                explicit: false,
                children: HashMap::new(),
            });

        if child.spelling != component {
            return Err(ARCHIVE_PATH_COLLISION.into());
        }

        if is_final {
            if child.explicit {
                return Err(ARCHIVE_PATH_COLLISION.into());
            }
            if is_directory {
                if child.kind == ArchivePathKind::File {
                    return Err(ARCHIVE_PATH_COLLISION.into());
                }
                child.explicit = true;
            } else {
                if child.kind == ArchivePathKind::Directory && !child.children.is_empty() {
                    return Err(ARCHIVE_PATH_COLLISION.into());
                }
                child.kind = ArchivePathKind::File;
                child.explicit = true;
            }
        } else if child.kind == ArchivePathKind::File {
            return Err(ARCHIVE_PATH_COLLISION.into());
        }

        node = child;
    }

    Ok(())
}

pub fn verified_archive(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<(ZipArchive<File>, String, AppFootprint), String> {
    if expected_sha256.is_some_and(|expected| {
        !Regex::new(r"(?i)^[0-9a-f]{64}$")
            .unwrap()
            .is_match(expected)
    }) {
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
    let actual_sha256 = format!("{:x}", hash.finalize());
    if expected_sha256.is_some_and(|expected| !actual_sha256.eq_ignore_ascii_case(expected)) {
        return Err("IPA checksum mismatch; refusing extraction".into());
    }
    file.rewind().map_err(|e| e.to_string())?;
    let mut archive = ZipArchive::new(file).map_err(|e| e.to_string())?;
    if archive.len() > 100_000 {
        return Err("Too many IPA archive entries".into());
    }
    let mut paths = ArchivePathNode::root();
    let mut indexed_path_components = 0;
    let mut total = 0u64;
    let mut app_bundle_size = 0u64;
    let mut app_file_sizes = Vec::new();
    let mut manifest_index = None;
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).map_err(|e| e.to_string())?;
        let name = member.name().to_owned();
        let declared_size = member.size();
        if name == "Payload/YouTube.app/Info.plist" && declared_size > 4 * 1024 * 1024 {
            return Err("Info.plist exceeds safety limit".into());
        }
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
        register_archive_path(
            &mut paths,
            &name,
            member.is_dir(),
            &mut indexed_path_components,
        )?;
        total = total
            .checked_add(declared_size)
            .ok_or("IPA decompressed size exceeds safety limit")?;
        if !member.is_dir()
            && (name == "Payload/YouTube.app/" || name.starts_with("Payload/YouTube.app/"))
        {
            app_bundle_size = app_bundle_size
                .checked_add(declared_size)
                .ok_or("IPA decompressed size exceeds safety limit")?;
            app_file_sizes.push(declared_size);
        }
        if total > 8 * 1024 * 1024 * 1024 {
            return Err("IPA decompressed size exceeds safety limit".into());
        }
        if declared_size > 64 * 1024 * 1024 && member.compressed_size() == 0 {
            return Err("Suspicious archive compression ratio".into());
        }
        if member.compressed_size() != 0
            && (declared_size as u128) > (member.compressed_size() as u128) * 2000
        {
            return Err("Suspicious archive compression ratio".into());
        }
        if name == "Payload/YouTube.app/Info.plist" {
            manifest_index = Some(index);
        }

        // Read every entry to EOF so zip validates compressed data and CRC
        // instead of silently discarding unread member contents.
        let mut actual_size = 0u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            let count = member
                .read(&mut buffer)
                .map_err(|error| format!("Invalid IPA archive member data: {error}"))?;
            if count == 0 {
                break;
            }
            actual_size = actual_size
                .checked_add(count as u64)
                .ok_or("IPA decompressed size exceeds safety limit")?;
            if actual_size > declared_size {
                return Err("IPA archive member exceeds its declared size".into());
            }
        }
        if actual_size != declared_size {
            return Err("IPA archive member size does not match its declaration".into());
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
    drop(plist_file);
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
    let footprint = AppFootprint {
        logical_bytes: app_bundle_size,
        file_sizes: app_file_sizes,
        directories: archive_directory_count(&paths),
    };
    Ok((archive, version.to_owned(), footprint))
}

/// Validates a local IPA's structure without treating a locally computed digest as authentication.
pub fn validate_local_ipa(path: &Path) -> Result<(), String> {
    verified_archive(path, None).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_archive_path_index_depth_and_size() {
        let mut root = ArchivePathNode::root();
        let mut indexed_components = 0;
        let deep_path = vec!["x"; MAX_ARCHIVE_PATH_COMPONENTS_PER_ENTRY + 1].join("/");
        let error = register_archive_path(&mut root, &deep_path, false, &mut indexed_components)
            .unwrap_err();
        assert!(error.contains("too many path components"), "{error}");

        let mut root = ArchivePathNode::root();
        let mut indexed_components = MAX_ARCHIVE_PATH_COMPONENTS;
        let error =
            register_archive_path(&mut root, "Payload", true, &mut indexed_components).unwrap_err();
        assert!(error.contains("too many path components"), "{error}");
    }
}
