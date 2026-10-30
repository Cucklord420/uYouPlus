use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::process;

fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
    args.windows(2).any(|pair| pair[0] == flag && pair[1] == value)
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_millis()
}

fn emit_http_status(args: &[String], status: u16, retry_after: Option<&str>) {
    let write_out = args
        .windows(2)
        .find(|pair| pair[0] == "--write-out")
        .map(|pair| pair[1].as_str());
    if write_out.is_some_and(|value| value.contains("__UYOU_RETRY_AFTER__")) {
        eprintln!("__UYOU_HTTP_STATUS__{status}");
        if let Some(retry_after) = retry_after {
            eprintln!("__UYOU_RETRY_AFTER__{retry_after}");
        } else {
            eprintln!("__UYOU_RETRY_AFTER__");
        }
    } else {
        eprintln!("__UYOU_HTTP_STATUS__{status}");
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let required = [
        ("--proto", "=https"),
        ("--proto-redir", "=https"),
        ("--max-redirs", "5"),
        ("--connect-timeout", "30"),
        ("--max-time", "600"),
        ("--max-filesize", "536870912"),
        ("--output", "-"),
    ];
    let supported_write_out = has_pair(
        &args,
        "--write-out",
        "%{stderr}__UYOU_HTTP_STATUS__%{http_code}\n__UYOU_RETRY_AFTER__%header{retry-after}\n",
    );
    if !["--fail", "--location", "--silent", "--show-error"]
        .iter()
        .all(|flag| args.iter().any(|arg| arg == flag))
        || !required
            .iter()
            .all(|(flag, value)| has_pair(&args, flag, value))
        || !supported_write_out
        || !args
            .last()
            .is_some_and(|url| url.starts_with("https://repo.miro92.com/debs/com.miro.uyou_"))
    {
        eprintln!("required HTTPS, timeout, size, or release URL policy was not passed");
        process::exit(97);
    }

    if let Some(marker) = env::var_os("SYNTHETIC_CURL_MARKER") {
        File::create(marker).expect("create invocation marker");
    }
    if let (Some(source), Some(destination)) = (
        env::var_os("SYNTHETIC_CACHE_SOURCE"),
        env::var_os("SYNTHETIC_CACHE_DESTINATION"),
    ) {
        std::fs::copy(source, destination).expect("publish synthetic competing cache");
    }
    if env::var_os("SYNTHETIC_CURL_FAILURE").is_some() {
        if let Some(marker) = env::var_os("SYNTHETIC_CURL_ATTEMPT_MARKER") {
            let previous = fs::read_to_string(&marker)
                .ok()
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or(0);
            fs::write(marker, (previous + 1).to_string())
                .expect("write synthetic attempt count");
        }
        emit_http_status(&args, 503, None);
        io::stdout()
            .write_all(b"HTTP 503 synthetic error response")
            .expect("write simulated error body");
        process::exit(22);
    }
    let source = env::var_os("SYNTHETIC_DEB").expect("synthetic source package path");

    if let Some(retry_after) = env::var_os("SYNTHETIC_CURL_RETRY_AFTER") {
        let attempts = env::var_os("SYNTHETIC_CURL_ATTEMPT_MARKER")
            .expect("synthetic curl attempt marker path");
        let retry_marker = env::var_os("SYNTHETIC_CURL_RETRY_MARKER")
            .expect("synthetic Retry-After marker path");
        let previous = fs::read_to_string(&attempts)
            .ok()
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or(0);
        fs::write(&attempts, (previous + 1).to_string()).expect("write synthetic attempt count");
        if previous == 0 {
            fs::write(&retry_marker, now_millis().to_string())
                .expect("write synthetic Retry-After start time");
            emit_http_status(&args, 503, retry_after.to_str());
            io::stdout()
                .write_all(b"HTTP 503 synthetic error response")
                .expect("write simulated error body");
            process::exit(22);
        }

        let first_attempt_millis = fs::read_to_string(retry_marker)
            .expect("read synthetic Retry-After start time")
            .parse::<u128>()
            .expect("parse synthetic Retry-After start time");
        if now_millis().saturating_sub(first_attempt_millis) < 1_750 {
            emit_http_status(&args, 503, retry_after.to_str());
            io::stdout()
                .write_all(b"HTTP 503 Retry-After has not elapsed")
                .expect("write simulated early retry body");
            process::exit(22);
        }
    }

    if env::var_os("SYNTHETIC_CURL_PARTIAL_RETRY").is_some() {
        let marker = env::var_os("SYNTHETIC_CURL_ATTEMPT_MARKER")
            .expect("synthetic curl attempt marker path");
        if has_pair(&args, "--retry", "2") {
            // Model curl's built-in retry with stdout: failed bytes remain in
            // the pipe before the successful response is written.
            io::stdout()
                .write_all(b"!<arch>\npartial response")
                .expect("write first simulated response");
            let mut input = File::open(source).expect("open synthetic source package");
            io::copy(&mut input, &mut io::stdout()).expect("write retried synthetic package");
            fs::write(marker, b"1").expect("write synthetic attempt count");
            return;
        }

        let previous = fs::read_to_string(&marker)
            .ok()
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or(0);
        fs::write(&marker, (previous + 1).to_string()).expect("write synthetic attempt count");
        if previous == 0 {
            io::stdout()
                .write_all(b"!<arch>\npartial response")
                .expect("write partial synthetic package");
            process::exit(28);
        }
    }

    let mut input = File::open(source).expect("open synthetic source package");
    io::copy(&mut input, &mut io::stdout()).expect("write synthetic package bytes");
}
