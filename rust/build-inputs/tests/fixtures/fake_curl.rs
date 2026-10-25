use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::process;

fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
    args.windows(2).any(|pair| pair[0] == flag && pair[1] == value)
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
        ("--retry", "2"),
        ("--output", "-"),
    ];
    if !["--fail", "--location", "--silent", "--show-error"]
        .iter()
        .all(|flag| args.iter().any(|arg| arg == flag))
        || !required
            .iter()
            .all(|(flag, value)| has_pair(&args, flag, value))
        || !args
            .last()
            .is_some_and(|url| url.starts_with("https://repo.miro92.com/debs/com.miro.uyou_"))
    {
        eprintln!("required HTTPS, timeout, size, retry, or release URL policy was not passed");
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
        io::stdout()
            .write_all(b"HTTP 503 synthetic error response")
            .expect("write simulated error body");
        process::exit(22);
    }
    let source = env::var_os("SYNTHETIC_DEB").expect("synthetic source package path");
    let mut input = File::open(source).expect("open synthetic source package");
    io::copy(&mut input, &mut io::stdout()).expect("write synthetic package bytes");
}
