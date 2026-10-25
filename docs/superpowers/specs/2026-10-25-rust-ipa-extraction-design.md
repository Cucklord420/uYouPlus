# Rust IPA validation and extraction design

**Intent.** Resolve RustyNuts #48 by making the existing Rust build-inputs command the implementation for the IPA trust boundary. An untrusted archive must be fully checked and unpacked outside the source checkout; only the validated `Payload/YouTube.app` bundle may be copied into a new Theos input directory.

**Goals.**
- Preserve the existing URL, operator-supplied SHA-256, archive path, size, duplicate, symlink, special-file, member allowlist, and version checks.
- Move ZIP extraction and checkout promotion from shell utilities into the Rust IPA command.
- Keep the new archive, extraction, and workflow regressions in Rust.
- Preserve the HTTPS-only download and staging cleanup.

**Non-goals.**
- The supplied URL and digest do not establish independent publisher authenticity.
- Do not merge Debian authentication or the separate ZIP case-fold/Unicode collision finding #58 into this change.
- Do not claim an authorized macOS/Theos build, signing, installation, or device test without performing it.

**Approaches.**
1. Keep the Python validator and shell `unzip`/copy path: rejected because new executable code and tests must be Rust.
2. Keep extraction in shell but call Rust for validation: rejected because untrusted-member extraction remains outside the Rust boundary.
3. Extend the current Rust IPA command to validate, extract to a fresh staging directory, and copy only the app bundle to a fresh destination: selected by the user's explicit Rust-port choice. It reuses the existing `zip`, `plist`, and `sha2` dependencies and leaves HTTPS download orchestration in the current workflow.

**Constraints and acceptance.**
- Keep the work on the existing PR #14 branch and leave the PR Draft while authorized macOS compatibility and independent review remain outstanding.
- Reject invalid checksums, unsafe or duplicate paths, links, FIFOs and other special files, unexpected roots, and unsafe/pre-existing destinations without changing checkout content.
- Accept the two reviewed root metadata files but do not copy them into the checkout.
- Copy the app's file permission bits so executable bundle files retain their build behavior.
- Run Rust formatting, strict Clippy, Rust regressions, workflow validation, and exact-head Linux/Windows CI. Record the missing macOS/device evidence honestly.
