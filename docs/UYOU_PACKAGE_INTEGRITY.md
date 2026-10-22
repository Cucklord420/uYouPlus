# uYou Debian package trust boundary

The build embeds code from a third-party `com.miro.uyou_<version>_iphoneos-arm.deb` archive. A valid HTTPS URL or versioned filename **does not authenticate its bytes**. The existing SHA-256 input for the decrypted YouTube IPA is unrelated to this dependency.

Before any non-jailbroken build, independently establish and review the expected SHA-256 of the exact uYou Debian archive. Obtain it from a trustworthy release record or trusted, independently verified artifact. **Do not derive the approved digest from the same untrusted download during the build.** Do not invent a digest.

- GitHub Actions: provide `uyou_deb_sha256` in the manual workflow alongside the existing YouTube IPA hash.
- Local build: export `UYOU_DEB_SHA256` with that reviewed 64-hex-digit value before invoking `./build.sh`. Local build and CI reject an absent or invalid value.
- Cached packages are rechecked, downloads are limited to HTTPS with bounded time/size, and the archive hash is validated before package extraction. A mismatch or missing hash intentionally stops the build.
- The synthetic offline tests exercise hash mismatch, error bodies, symlinks, empty/oversized packages and the CI/Makefile gate. They **do not** establish the authenticity of a particular upstream archive, prove the entire package is safe, execute Theos, or test on an installed iPhone.

This change intentionally makes unauthenticated existing build commands fail closed. Reviewers must check the upstream digest's independent provenance and test the actual macOS build before marking the protection complete. The rest of the dependency/toolchain and IPA extraction boundary require their own review.
