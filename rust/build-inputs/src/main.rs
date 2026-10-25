// SPDX-License-Identifier: GPL-3.0-only
// Read-only Rust input validation for the existing manual IPA build.
// Ported from the inputs command in scripts/build_checks.py.

use regex::Regex;
use std::net::IpAddr;
use url::Url;

fn valid(pattern: &str, value: &str) -> bool {
    Regex::new(pattern).expect("static regex").is_match(value)
}

fn validate(
    url: &str,
    digest: &str,
    version: &str,
    bundle: &str,
    app: &str,
) -> Result<(), &'static str> {
    if !valid(r"(?i)^[0-9a-f]{64}$", digest) {
        return Err("A 64-character SHA-256 checksum is required for the IPA");
    }
    if !valid(r"^[0-9]+(\.[0-9]+){1,4}$", version) {
        return Err("uYou version must contain only digits and dots");
    }
    if !valid(
        r"^[A-Za-z][A-Za-z0-9-]*(\.[A-Za-z][A-Za-z0-9-]*){1,8}$",
        bundle,
    ) {
        return Err("Invalid bundle identifier");
    }
    if !valid(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$", app) || app.ends_with(' ') {
        return Err("App display name must use simple printable characters (max 40)");
    }
    if url
        .chars()
        .any(|ch| ch.is_ascii_control() || ch == ' ' || ch.is_ascii_whitespace())
    {
        return Err("URL contains spaces or control characters");
    }
    // The URL parser canonicalizes percent-encoded and internationalized hostnames.
    // Check the original authority first so rejected Python inputs cannot become
    // apparently valid public DNS names through that normalization.
    let (_, after_scheme) = url.split_once("://").ok_or("Invalid IPA URL")?;
    let raw_authority = after_scheme
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or("");
    if raw_authority.is_empty()
        || raw_authority
            .chars()
            .any(|ch| !ch.is_ascii() || ch == '%' || ch == '\\')
    {
        return Err("Invalid public DNS hostname");
    }
    // Python urlsplit() validates the original path. Url::parse normalizes
    // terminal /./ and /../ segments, which can change the file-path check.
    let path_and_suffix = &after_scheme[raw_authority.len()..];
    let raw_path = path_and_suffix
        .split(&['?', '#'][..])
        .next()
        .unwrap_or("");
    if raw_path.is_empty() || raw_path.ends_with('/') {
        return Err("IPA URL must point to a file");
    }
    let parsed = Url::parse(url).map_err(|_| "Invalid IPA URL")?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some_and(|fragment| !fragment.is_empty())
    {
        return Err("IPA URL must use HTTPS without credentials or fragments");
    }
    if parsed.port().is_some_and(|p| p != 443) {
        return Err("Nonstandard HTTPS ports are not allowed");
    }
    let host = parsed.host_str().ok_or("Invalid IPA URL")?;
    let hostname = host.trim_end_matches('.').to_ascii_lowercase();
    if hostname.parse::<IpAddr>().is_ok() || hostname.starts_with('[') {
        return Err("IP literal URLs are prohibited");
    }
    if hostname == "localhost"
        || [".localhost", ".local", ".internal", ".test", ".invalid"]
            .iter()
            .any(|suffix| hostname.ends_with(suffix))
    {
        return Err("Local network hosts are prohibited");
    }
    let label = r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$";
    if !hostname.contains('.')
        || hostname.len() > 253
        || hostname.split('.').any(|part| !valid(label, part))
    {
        return Err("Invalid public DNS hostname");
    }
    Ok(())
}

fn main() {
    let mut url = None;
    let mut sha = None;
    let mut version = None;
    let mut bundle = None;
    let mut app = None;
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("inputs") {
        eprintln!("Usage: uyouplus-inputs inputs --url URL --sha256 DIGEST --version VERSION --bundle ID --app NAME");
        std::process::exit(2);
    }
    while let Some(key) = args.next() {
        let Some(value) = args.next() else {
            eprintln!("Missing value for build argument");
            std::process::exit(2);
        };
        match key.as_str() {
            "--url" => url = Some(value),
            "--sha256" => sha = Some(value),
            "--version" => version = Some(value),
            "--bundle" => bundle = Some(value),
            "--app" => app = Some(value),
            _ => {
                eprintln!("Unrecognized build argument");
                std::process::exit(2);
            }
        }
    }
    let Some((url, sha, version, bundle, app)) = url
        .zip(sha)
        .zip(version)
        .zip(bundle)
        .zip(app)
        .map(|((((url, sha), version), bundle), app)| (url, sha, version, bundle, app))
    else {
        eprintln!("Missing required build argument");
        std::process::exit(2);
    };
    match validate(&url, &sha, &version, &bundle, &app) {
        Ok(()) => println!("Operator input validation passed"),
        Err(message) => {
            eprintln!("Build input rejected: {message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn all_existing_15_input_cases() {
        let url = "https://downloads.example.org/my.ipa";
        let sha = "f".repeat(64);
        let version = "3.0.3";
        let bundle = "com.google.ios.youtube";
        let app = "YouTube";
        let cases = [
            (url, version, bundle, app, true),
            (
                "https://downloads.example.org/my.ipa?token=abc&expires=123",
                version,
                bundle,
                app,
                true,
            ),
            (
                "http://downloads.example.org/my.ipa",
                version,
                bundle,
                app,
                false,
            ),
            (
                "https://user:pw@downloads.example.org/my.ipa",
                version,
                bundle,
                app,
                false,
            ),
            ("https://localhost/my.ipa", version, bundle, app, false),
            ("https://127.0.0.1/my.ipa", version, bundle, app, false),
            ("https://host.internal/my.ipa", version, bundle, app, false),
            (
                "https://downloads.example.org:8443/my.ipa",
                version,
                bundle,
                app,
                false,
            ),
            (
                "https://downloads.example.org/my.ipa#archive",
                version,
                bundle,
                app,
                false,
            ),
            (
                "https://downloads.example.org/my.ipa\ncommand",
                version,
                bundle,
                app,
                false,
            ),
            (url, "3.0.3; touch /tmp/pwn", bundle, app, false),
            (url, version, "com.example.youtube#evil", app, false),
            (url, version, bundle, "YouTube$(touch abc)", false),
            (url, version, bundle, "YouTube Test-1", true),
        ];
        for (u, version, bundle, app, want) in cases {
            assert_eq!(
                validate(u, &sha, version, bundle, app).is_ok(),
                want,
                "{u} {version}"
            );
        }
        assert!(validate(url, "", version, bundle, app).is_err());
    }

    #[test]
    fn differential_behavior_against_actual_python_entrypoint() {
        let py = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/build_checks.py");
        let sha = "f".repeat(64);
        let cases = [
            "https://downloads.example.org/my.ipa",
            "https://127.0.0.1/a.ipa",
            "https://localhost/a.ipa",
            "https://host.internal/a.ipa",
            "https://host.test/a.ipa",
            "https://downloads.example.org:8443/a.ipa",
            "https://downloads.example.org/a.ipa#fragment",
            "https://downloads.example.org/",
            "https://downloads.example.org/a.ipa?token=abc",
            "https://downloads.example.org/a.ipa#",
            "https://downloads.example.org/a/.",
            "https://downloads.example.org/a/..",
            "https://downloads.example.org/.",
            "https://downloads.example.org/a/../",
            "https://ex%61mple.org/test.ipa",
            "https://bücher.example.org/test.ipa",
            "https://exa\\\\mple.org/test.ipa",
            "https:downloads.example.org/test.ipa",
            "https://downloads.example.org/%66ile.ipa?token=abc",
        ];
        for url in cases {
            let rust_ok = validate(url, &sha, "3.0.3", "com.google.ios.youtube", "YouTube").is_ok();
            let original = Command::new("python3")
                .arg(&py)
                .args([
                    "inputs",
                    "--url",
                    url,
                    "--sha256",
                    &sha,
                    "--version",
                    "3.0.3",
                    "--bundle",
                    "com.google.ios.youtube",
                    "--app",
                    "YouTube",
                ])
                .output()
                .expect("Python comparator");
            assert_eq!(
                rust_ok,
                original.status.success(),
                "Different behavior for {url}"
            );
        }
    }

    #[test]
    fn url_normalization_edges_match_original_python_entrypoint() {
        let py = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/build_checks.py");
        let sha = "f".repeat(64);
        let cases = [
            ("https://ex%61mple.org/test.ipa", false),
            ("https://bücher.example.org/test.ipa", false),
            ("https://exa\\\\mple.org/test.ipa", false),
            ("https:downloads.example.org/test.ipa", false),
            ("https://downloads.example.org/a/.", true),
            ("https://downloads.example.org/a/..", true),
            ("https://downloads.example.org/.", true),
            ("https://downloads.example.org/a/../", false),
            ("https://downloads.example.org/a.ipa#", true),
            ("https://downloads.example.org/%66ile.ipa?token=abc", true),
        ];
        for (url, expected) in cases {
            let rust_ok = validate(url, &sha, "3.0.3", "com.google.ios.youtube", "YouTube").is_ok();
            let original = Command::new("python3")
                .arg(&py)
                .args([
                    "inputs", "--url", url, "--sha256", &sha, "--version", "3.0.3",
                    "--bundle", "com.google.ios.youtube", "--app", "YouTube",
                ])
                .output()
                .expect("Python comparator");
            assert_eq!(rust_ok, original.status.success(), "Different behavior for {url}");
            assert_eq!(rust_ok, expected, "Unexpected validation result for {url}");
        }
    }

    #[test]
    fn bad_hash_version_and_app_rejected() {
        let valid_hash = "a".repeat(64);
        assert!(validate(
            "https://files.example.org/test.ipa",
            &valid_hash,
            "1.2",
            "com.app",
            "Example"
        )
        .is_ok());
        assert!(validate(
            "https://files.example.org/test.ipa",
            &valid_hash[..63],
            "1.2",
            "com.app",
            "Example"
        )
        .is_err());
        assert!(validate(
            "https://files.example.org/test.ipa",
            &valid_hash,
            "1",
            "com.app",
            "Example"
        )
        .is_err());
        assert!(validate(
            "https://files.example.org/test.ipa",
            &valid_hash,
            "1.2.3.4.5.6",
            "com.app",
            "Example"
        )
        .is_err());
    }
}
