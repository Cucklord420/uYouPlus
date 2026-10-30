// SPDX-License-Identifier: GPL-3.0-only
// Shared validation policy for manual build inputs and IPA downloads.

pub mod archive;

use regex::Regex;
use std::net::IpAddr;
use url::Url;

fn valid(pattern: &str, value: &str) -> bool {
    Regex::new(pattern).expect("static regex").is_match(value)
}

pub fn validate_ipa_url(url: &str) -> Result<(), &'static str> {
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
    let raw_path = path_and_suffix.split(&['?', '#'][..]).next().unwrap_or("");
    if raw_path.is_empty() || raw_path.ends_with('/') {
        return Err("IPA URL must point to a file");
    }
    let parsed = Url::parse(url).map_err(|_| "Invalid IPA URL")?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed
            .fragment()
            .is_some_and(|fragment| !fragment.is_empty())
    {
        return Err("IPA URL must use HTTPS without credentials or fragments");
    }
    if parsed.port().is_some_and(|port| port != 443) {
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
