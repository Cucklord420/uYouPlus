# uYou Debian package trust boundary

The build embeds code from the third-party `com.miro.uyou_<version>_iphoneos-arm.deb` archive. A valid HTTPS URL or versioned filename **does not authenticate its bytes**. The SHA-256 input for the decrypted YouTube IPA is unrelated to this dependency.

Before a non-jailbroken build, independently obtain and review the SHA-256 of the exact uYou Debian archive. Use a trustworthy release record or trusted, independently verified artifact. **Do not derive the approved digest from the same untrusted download during the build.** Do not invent a digest.

- GitHub Actions requires the separate `uyou_deb_sha256` input and validates it with the Rust `uyou-deb` command before invoking Make.
- Local builds use `UYOU_DEB_SHA256` and the `UYOU_VERSION` variable. The preflight validates both before the Makefile can expand the version. For the default local version, run:

  ```sh
  export UYOU_VERSION="${UYOU_VERSION:-3.0.3}"
  cargo run --quiet --manifest-path rust/build-inputs/Cargo.toml --bin uyou-deb -- validate &&
    UYOU_DEB_INPUTS_VALIDATED=1 ./build.sh
  ```

- Package versions are restricted to 1–40 safe ASCII characters beginning with a digit. Package paths and cached files must be real directories and regular files; symlinked package parents and files are rejected.
- The Rust command rechecks cached packages, downloads only from the fixed HTTPS release URL with HTTPS-only redirects, bounded time/size, and retries, and verifies the SHA-256 before no-clobber cache promotion.
- Debian `.deb` files are outer `ar` archives, not standalone TAR files. After digest verification, Rust invokes `dpkg-deb --extract` into a fresh staging directory beside the build payload. It checks the required dylib and bundle in that staged tree, then replaces the existing `Library` directory with backup-and-restore handling. Stale files cannot satisfy staged-payload checks.
- `JAILBROKEN=1` continues to bypass the Debian digest and preflight because that path does not download or extract the package. Its localization packaging behavior remains available.
- Rust regressions use fictional `.deb` archives and an offline Rust `curl` fixture. They cover digest and archive rejection, symlink boundaries, bounded downloads, cache promotion, stale-payload replacement, failed replacement preservation, Makefile preflight order, and the jailbroken path.

These checks do **not** establish the authenticity of a particular upstream archive, prove the entire package is safe, execute Theos, establish redistribution rights, or test an installed iPhone. Independent vendor-digest provenance, security review, and an authorized macOS/Theos compatibility build remain required before merge.
