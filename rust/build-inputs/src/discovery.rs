// SPDX-License-Identifier: GPL-3.0-only
// Find one root-level IPA file or app bundle without following symlinks.

use std::{
    ffi::OsStr,
    fs,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

fn find_root_input(root: &Path) -> Result<PathBuf, String> {
    let entries = fs::read_dir(root)
        .map_err(|error| format!("Cannot read the root input directory: {error}"))?;
    let mut selected = None;

    for entry in entries {
        let entry = entry.map_err(|error| {
            format!("Cannot inspect a root directory entry: {error}")
        })?;
        let path = entry.path();
        let extension = path.extension();
        let is_ipa = extension == Some(OsStr::new("ipa"));
        let is_app = extension == Some(OsStr::new("app"));

        if !is_ipa && !is_app {
            continue;
        }

        let file_type = entry.file_type().map_err(|error| {
            format!("Cannot inspect candidate type for {}: {error}", path.display())
        })?;
        let is_valid = (is_ipa && file_type.is_file()) || (is_app && file_type.is_dir());
        if !is_valid {
            continue;
        }

        if selected.is_some() {
            return Err("Multiple root-level IPA/app candidates found".to_owned());
        }
        selected = Some(path);
    }

    selected.ok_or_else(|| "No root-level regular .ipa file or .app directory found".to_owned())
}

pub fn write_root_input() -> Result<(), String> {
    let path = find_root_input(Path::new("."))?;
    let mut bytes = Vec::with_capacity(path.as_os_str().as_bytes().len() + 1);
    bytes.extend_from_slice(path.as_os_str().as_bytes());
    bytes.push(0);

    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&bytes)
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("Cannot write the selected input path: {error}"))
}
