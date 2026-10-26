// SPDX-License-Identifier: GPL-3.0-only
// Rust input validation for the existing manual IPA build.

use regex::Regex;
use uyouplus_inputs::validate_ipa_url;

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
    validate_ipa_url(url)?;
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
    fn url_normalization_edges_match_expected_policy() {
        let sha = "f".repeat(64);
        let cases = [
            ("https://downloads.example.org/my.ipa", true),
            ("https://127.0.0.1/a.ipa", false),
            ("https://localhost/a.ipa", false),
            ("https://host.internal/a.ipa", false),
            ("https://host.test/a.ipa", false),
            ("https://downloads.example.org:8443/a.ipa", false),
            ("https://downloads.example.org/a.ipa#fragment", false),
            ("https://downloads.example.org/", false),
            ("https://downloads.example.org/a.ipa?token=abc", true),
            ("https://downloads.example.org/a.ipa#", true),
            ("https://downloads.example.org/a/.", true),
            ("https://downloads.example.org/a/..", true),
            ("https://downloads.example.org/.", true),
            ("https://downloads.example.org/a/../", false),
            ("https://ex%61mple.org/test.ipa", false),
            ("https://bücher.example.org/test.ipa", false),
            ("https://exa\\mple.org/test.ipa", false),
            ("https:downloads.example.org/test.ipa", false),
            ("https://downloads.example.org/%66ile.ipa?token=abc", true),
        ];
        for (url, expected) in cases {
            let rust_ok = validate(url, &sha, "3.0.3", "com.google.ios.youtube", "YouTube").is_ok();
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
