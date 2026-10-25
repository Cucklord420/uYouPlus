use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const INFO_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleVersion</key><string>19.25.4</string></dict></plist>"#;

fn make_ipa(path: &Path, entries: &[(&str, &[u8], Option<u32>)]) -> String {
    let file = File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    for &(name, bytes, mode) in entries {
        let mut options =
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        if let Some(mode) = mode {
            options = options.unix_permissions(mode);
        }
        writer.start_file(name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap();
    let contents = fs::read(path).unwrap();
    format!("{:x}", Sha256::digest(contents))
}

fn valid_entries() -> Vec<(&'static str, &'static [u8], Option<u32>)> {
    vec![
        ("Payload/YouTube.app/Info.plist", INFO_PLIST, Some(0o644)),
        (
            "Payload/YouTube.app/Frameworks/helper",
            b"synthetic executable",
            Some(0o755),
        ),
        ("iTunesMetadata.plist", b"approved root metadata", None),
        ("iTunesArtwork", b"approved artwork", None),
    ]
}

fn run_prepare(ipa: &Path, digest: &str, staging: &Path, payload: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ipa"))
        .args(["ipa", "--file"])
        .arg(ipa)
        .arg("--sha256")
        .arg(digest)
        .arg("--staging-dir")
        .arg(staging)
        .arg("--payload-destination")
        .arg(payload)
        .output()
        .unwrap()
}

fn checkout_fixture() -> (TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let checkout = temp.path().join("checkout");
    let main = checkout.join("main");
    fs::create_dir_all(&main).unwrap();
    fs::write(main.join("Makefile"), b"trusted build source").unwrap();
    let staging = temp.path().join("runner-temp").join("extracted");
    fs::create_dir_all(staging.parent().unwrap()).unwrap();
    let payload = main.join("Payload");
    (temp, checkout, staging, payload)
}

#[test]
fn stages_and_promotes_only_the_validated_app_bundle() {
    let (temp, checkout, staging, payload) = checkout_fixture();
    let ipa = temp.path().join("valid.ipa");
    let digest = make_ipa(&ipa, &valid_entries());

    let output = run_prepare(&ipa, &digest, &staging, &payload);
    assert!(
        output.status.success(),
        "Rust IPA preparation rejected valid fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "19.25.4");
    assert_eq!(
        fs::read(staging.join("Payload/YouTube.app/Info.plist")).unwrap(),
        INFO_PLIST
    );
    assert_eq!(
        fs::read(payload.join("YouTube.app/Frameworks/helper")).unwrap(),
        b"synthetic executable"
    );
    assert_eq!(
        fs::read(checkout.join("main/Makefile")).unwrap(),
        b"trusted build source"
    );
    assert!(!payload.join("iTunesMetadata.plist").exists());
    assert!(!payload.join("iTunesArtwork").exists());
    assert!(!staging.join("iTunesMetadata.plist").exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(payload.join("YouTube.app/Frameworks/helper"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111, "app executable mode was lost");
    }
}

#[test]
fn rejects_unexpected_members_before_creating_output_or_changing_checkout() {
    let (temp, checkout, staging, payload) = checkout_fixture();
    let ipa = temp.path().join("unexpected.ipa");
    let mut entries = valid_entries();
    entries.push(("Makefile", b"untrusted replacement", None));
    let digest = make_ipa(&ipa, &entries);

    let output = run_prepare(&ipa, &digest, &staging, &payload);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unapproved archive member"),
        "unexpected rejection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(checkout.join("main/Makefile")).unwrap(),
        b"trusted build source"
    );
    assert!(!staging.exists());
    assert!(!payload.exists());
}

#[test]
fn refuses_a_preexisting_payload_without_overwriting_it() {
    let (temp, checkout, staging, payload) = checkout_fixture();
    fs::create_dir(&payload).unwrap();
    fs::write(payload.join("marker"), b"preexisting payload").unwrap();
    let ipa = temp.path().join("valid.ipa");
    let digest = make_ipa(&ipa, &valid_entries());

    let output = run_prepare(&ipa, &digest, &staging, &payload);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("destination already exists"),
        "unexpected rejection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(payload.join("marker")).unwrap(),
        b"preexisting payload"
    );
    assert_eq!(
        fs::read(checkout.join("main/Makefile")).unwrap(),
        b"trusted build source"
    );
    assert!(!staging.exists());
}

#[test]
fn refuses_a_preexisting_staging_directory_without_overwriting_it() {
    let (temp, checkout, staging, payload) = checkout_fixture();
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("marker"), b"preexisting staging data").unwrap();
    let ipa = temp.path().join("valid.ipa");
    let digest = make_ipa(&ipa, &valid_entries());

    let output = run_prepare(&ipa, &digest, &staging, &payload);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("destination already exists"),
        "unexpected rejection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(staging.join("marker")).unwrap(),
        b"preexisting staging data"
    );
    assert_eq!(
        fs::read(checkout.join("main/Makefile")).unwrap(),
        b"trusted build source"
    );
    assert!(!payload.exists());
}

#[cfg(unix)]
#[test]
fn refuses_symlink_payload_without_writing_through_it() {
    use std::os::unix::fs::symlink;

    let (temp, checkout, staging, payload) = checkout_fixture();
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("marker"), b"outside").unwrap();
    symlink(&outside, &payload).unwrap();
    let ipa = temp.path().join("valid.ipa");
    let digest = make_ipa(&ipa, &valid_entries());

    let output = run_prepare(&ipa, &digest, &staging, &payload);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("destination already exists"),
        "unexpected rejection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(outside.join("marker")).unwrap(), b"outside");
    assert_eq!(
        fs::read(checkout.join("main/Makefile")).unwrap(),
        b"trusted build source"
    );
    assert!(!staging.exists());
}
