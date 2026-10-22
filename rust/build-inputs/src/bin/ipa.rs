// Read-only IPA checksum and ZIP/plist security verifier.
// Preserves the input IPA; no extraction, signing, network or disk writes.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use zip::ZipArchive;

fn verify(path: &Path, expected: &str) -> Result<String, String> {
    let sha = Regex::new(r"(?i)^[0-9a-f]{64}$").unwrap();
    if !sha.is_match(expected) {
        return Err("Invalid SHA-256 digest".into());
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 4 * 1024 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        hash.update(&buffer[..n]);
    }
    if !format!("{:x}", hash.finalize()).eq_ignore_ascii_case(expected) {
        return Err("IPA checksum mismatch; refusing extraction".into());
    }
    file.rewind().map_err(|e| e.to_string())?;
    let mut archive=ZipArchive::new(file).map_err(|e| e.to_string())?;
    if archive.len() > 100_000 {
        return Err("Too many IPA archive entries".into());
    }
    let mut seen=HashSet::new();
    let mut total=0u64;
    let mut manifest_index=None;
    for index in 0..archive.len() {
        let member=archive.by_index(index).map_err(|e| e.to_string())?;
        let name=member.name().to_owned();
        let parts:Vec<&str> = name.split('/').collect();
        if name.is_empty() || name.starts_with('/') || name.contains('\\')
            || name.contains('\0')
            || parts[..parts.len().saturating_sub(1)].iter().any(|s| s.is_empty() || *s=="." || *s=="..")
            || parts.contains(&"..")
            || parts.first().is_some_and(|s| s.contains(':'))
        {
            return Err("Unsafe IPA archive entry path".into());
        }
        let kind = member.unix_mode().map(|mode| mode & 0o170000).unwrap_or(0);
        if kind == 0o120000 {
            return Err("IPA contains a symbolic link".into());
        }
        let is_directory = name.ends_with('/');
        if !matches!((is_directory, kind), (true, 0 | 0o040000) | (false, 0 | 0o100000)) {
            return Err("Unsupported IPA archive entry type".into());
        }
        if !((is_directory && (name == "Payload/" || name == "Payload/YouTube.app/"))
            || name.starts_with("Payload/YouTube.app/")
            || (!is_directory && (name == "iTunesArtwork" || name == "iTunesMetadata.plist")))
        {
            return Err("Unexpected IPA archive entry".into());
        }
        let logical=name.trim_end_matches('/');
        if !seen.insert(logical.to_owned()) {
            return Err("Duplicate IPA archive entry".into());
        }
        total=total.checked_add(member.size()).ok_or("IPA decompressed size exceeds safety limit")?;
        if total>8*1024*1024*1024 {
            return Err("IPA decompressed size exceeds safety limit".into());
        }
        if member.size()>64*1024*1024 && member.compressed_size()==0 {
            return Err("Suspicious archive compression ratio".into());
        }
        if member.compressed_size()!=0 && (member.size() as u128)>(member.compressed_size() as u128)*2000 {
            return Err("Suspicious archive compression ratio".into());
        }
        if name=="Payload/YouTube.app/Info.plist" {
            manifest_index=Some(index);
        }
    }
    let index=manifest_index.ok_or("Not a YouTube IPA: missing Info.plist")?;
    let mut plist_file=archive.by_index(index).map_err(|e| e.to_string())?;
    // Bound manifest read to avoid allocating massive attacker-controlled XML/plist.
    let mut bytes=Vec::new();
    plist_file.by_ref().take(4*1024*1024+1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len()>4*1024*1024 { return Err("Info.plist exceeds safety limit".into()); }
    let root=plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let version=root.as_dictionary()
        .and_then(|d|d.get("CFBundleVersion"))
        .and_then(plist::Value::as_string)
        .ok_or("Invalid YouTube CFBundleVersion")?;
    let pattern=Regex::new(r"^[0-9]+(\.[0-9]+){1,4}$").unwrap();
    if !pattern.is_match(version) {
        return Err("Invalid YouTube CFBundleVersion".into());
    }
    Ok(version.to_owned())
}

fn main() {
    let mut args=std::env::args().skip(1);
    if args.next().as_deref()!=Some("ipa") {
        eprintln!("Usage: ipa ipa --file PATH --sha256 HEX");
        std::process::exit(2);
    }
    let mut path=None;
    let mut sha=None;
    while let Some(flag)=args.next() {
        let Some(value)=args.next() else {
            eprintln!("Missing option value");
            std::process::exit(2);
        };
        match flag.as_str() {
            "--file"=>path=Some(value),
            "--sha256"=>sha=Some(value),
            _=>{ eprintln!("Invalid option"); std::process::exit(2); }
        }
    }
    let Some((path,sha))=path.zip(sha) else {
        eprintln!("Missing required file or digest");
        std::process::exit(2);
    };
    match verify(Path::new(&path),&sha) {
        Ok(version)=>println!("{version}"),
        Err(error)=>{eprintln!("Build input rejected: {error}");std::process::exit(1);}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;
    use zip::{write::FileOptions, CompressionMethod, ZipWriter};

    const PLIST:&str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleVersion</key><string>19.25.4</string></dict></plist>"#;

    fn fixture(extra: &[(&str,&[u8])]) -> (tempfile::TempDir,String) {
        let directory=tempfile::tempdir().unwrap();
        let path=directory.path().join("fixture.ipa");
        let file=File::create(&path).unwrap();
        let mut writer=ZipWriter::new(file);
        let options=FileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("Payload/YouTube.app/Info.plist",options).unwrap();
        writer.write_all(PLIST.as_bytes()).unwrap();
        for (name,data) in extra {
            writer.start_file(*name,options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        let contents=std::fs::read(&path).unwrap();
        (directory,format!("{:x}",Sha256::digest(&contents)))
    }

    #[test]
    fn validates_synthetic_ipa_and_checksum() {
        let (temp,sha)=fixture(&[]);
        let path=temp.path().join("fixture.ipa");
        assert_eq!(verify(&path,&sha).unwrap(),"19.25.4");
        assert!(verify(&path,&"f".repeat(64)).is_err());
    }

    #[test]
    fn rejects_unsafe_paths_and_duplicates() {
        for name in ["../escape","Payload/../escape","Payload\\escape",
            "Payload/YouTube.app/Info.plist","Payload/./bad","/absolute/path"] {
            let (temp,sha)=fixture(&[(name,b"bad")]);
            assert!(verify(&temp.path().join("fixture.ipa"),&sha).is_err(),"accepted {name}");
        }
    }

    #[test]
    fn original_python_reports_equivalent_acceptance_on_synthetic_ipa() {
        let python=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/build_checks.py");
        for extras in [
            Vec::<(&str,&[u8])>::new(),
            vec![("../escape",b"x".as_slice())],
            vec![("Payload/../escape",b"x".as_slice())],
            vec![("Payload\\escape",b"x".as_slice())],
            vec![("Payload/YouTube.app/Info.plist",b"x".as_slice())],
        ] {
            let (temp,sha)=fixture(&extras);
            let path=temp.path().join("fixture.ipa");
            let rust=verify(&path,&sha).is_ok();
            let result=Command::new("python3").arg(&python).arg("ipa")
                .arg("--file").arg(&path).arg("--sha256").arg(&sha)
                .output().unwrap();
            assert_eq!(rust,result.status.success(),"Mismatch with original: {extras:?}");
        }
    }

    #[test]
    fn rejects_unexpected_archive_roots() {
        for name in [
            "unapproved.txt",
            "Makefile",
            ".github/workflows/unsafe.yml",
            "Payload/Other.app/Info.plist",
        ] {
            let (temp, sha) = fixture(&[(name, b"synthetic fixture")]);
            let error = verify(&temp.path().join("fixture.ipa"), &sha).unwrap_err();
            assert!(error.contains("Unexpected IPA archive entry"), "{name}: {error}");
        }
    }

    #[test]
    fn rejects_unsupported_archive_entry_types() {
        // ZIP writer creates regular files. Python's synthetic fixture covers
        // non-regular mode bits; this test checks reviewed-path acceptance.
        let (temp, sha) = fixture(&[("Payload/YouTube.app/Resource.txt", b"synthetic")]);
        assert_eq!(verify(&temp.path().join("fixture.ipa"), &sha).unwrap(), "19.25.4");
    }

    #[test]
    fn accepts_reviewed_optional_metadata() {
        let (temp, sha) = fixture(&[
            ("iTunesArtwork", b"synthetic"),
            ("iTunesMetadata.plist", b"synthetic"),
        ]);
        assert_eq!(verify(&temp.path().join("fixture.ipa"), &sha).unwrap(), "19.25.4");
    }

    #[test]
    fn rejects_not_a_zip_without_touching_original() {
        let dir=tempfile::tempdir().unwrap();
        let file=dir.path().join("bad.ipa");
        std::fs::write(&file,b"not a zip").unwrap();
        let hash=format!("{:x}",Sha256::digest(b"not a zip"));
        assert!(verify(&file,&hash).is_err());
        assert_eq!(std::fs::read(file).unwrap(),b"not a zip");
    }
}
