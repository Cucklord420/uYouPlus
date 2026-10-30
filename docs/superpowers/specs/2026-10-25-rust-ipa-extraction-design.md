# Rust IPA validation and extraction design

**Intent.** Resolve RustyNuts #48 by making the existing Rust build-inputs command the implementation for the IPA trust boundary. An untrusted archive must be fully checked and unpacked outside the source checkout; only the validated `Payload/YouTube.app` bundle may be copied into a new Theos input directory.

**Goals.**
- Preserve the existing URL, operator-supplied SHA-256, archive path, size, duplicate, symlink, special-file, member allowlist, and version checks.
- Move ZIP extraction and checkout promotion from shell utilities into the Rust IPA command.
- Move the HTTPS download into the Rust IPA command so it can enforce byte limits while streaming.
- Keep the new archive, extraction, and workflow regressions in Rust.
- Reject path components that compare equal under Unicode canonical caseless matching, checking implicit directories and file/directory conflicts before output creation.
- Verify path-collision rejection and report actual case/normalization alias behavior on the macOS-15 runner using harmless temporary fixtures.
- Preserve HTTPS-only redirects, the 600-second request timeout, two retries, and staging cleanup.

**Non-goals.**
- The supplied URL and digest do not establish independent publisher authenticity.
- Debian package authentication remains a separate change.
- Do not claim an authorized macOS/Theos build, signing, installation, or device test without performing it.

**Approaches.**
1. Keep the Python validator and shell `unzip`/copy path: rejected because new executable code and tests must be Rust.
2. Keep extraction in shell but call Rust for validation: rejected because untrusted-member extraction remains outside the Rust boundary.
3. Extend the current Rust IPA command to download, validate, extract to a fresh staging directory, and copy only the app bundle to a fresh destination: selected by the user's explicit Rust-port choice. The downloader streams `curl` output through Rust's byte counter; the shell no longer owns transfer or archive processing.

**Approved resource policy.** The user selected a stricter 4 GiB hard download cap and a 4 GiB free-space reserve. Each attempt is limited to the smaller of the hard cap and the free space available above the reserve. Rust counts bytes as they arrive and ignores `Content-Length`; it never writes the byte that would exceed the limit. The URL uses the existing strict shared validation policy, is sent to `curl` through stdin rather than process arguments, and ambient `curl` configuration is disabled. HTTPS-only protocol and redirect rules, a 600-second per-attempt timeout, and two retries are retained. Rust removes each failed partial file before retrying or returning an error. Before creating extraction or payload output, it checks current free space for the declared app-bundle expansion and its promoted copy, plus the same 4 GiB reserve. The already-downloaded IPA is reflected in current free space. On a shared filesystem the check covers both copies together; on separate filesystems it checks each destination volume for its own copy and reserve. The existing 8 GiB ZIP expansion ceiling remains in force.

**Archive path semantics.** An IPA is rejected if any path component conflicts under canonical caseless matching: NFD, full default Unicode case folding using the Unicode 16.0.0 tables bundled by `caseless` 0.2.2, then NFD using `unicode-normalization` 0.1.26. This applies to every component prefix, including implicit directories, and rejects duplicates plus file/directory conflicts before staging is created. Matching is deliberately conservative across the extraction volume's case and normalization settings. The prefix index is capped at 128 components per entry and 1,000,000 components per archive to bound memory use.

**Allocation-budget correction (10-30-2026).** Logical ZIP sizes omit directory storage and file-allocation rounding. Preflight now rounds each app file using each destination's actual `statvfs` allocation unit, counts each unique implicit/explicit directory once, and budgets one directory-data block plus one metadata block per directory, one metadata block per file, and the new outer output directory. The Payload wrapper is conservatively counted for both copies. Shared-volume estimates are added before the 4 GiB reserve; separate volumes use their own allocation units and reserve. This is conservative headroom rather than an exact APFS bound. Live queries before directory creation and bounded file writes, after flushes, and during promotion fail closed on insufficient space or query failure and retain owned-output cleanup. They cannot reserve shared filesystem space against concurrent consumers. The 4 GiB hard input-download cap, 4 GiB reserve, HTTPS/timeout/retry policy, and 8 GiB logical ZIP expansion ceiling are unchanged. Regression coverage rejects the valid 7,801-file/975,002-directory archive with 5 GiB free without extracting its tree, and checks live-pressure cleanup with small fictional fixtures.

**Constraints and acceptance.**
- Keep the work on the existing PR #14 branch and leave the PR Draft while authorized macOS compatibility and independent review remain outstanding.
- Reject invalid checksums, unsafe or duplicate paths, links, FIFOs and other special files, unexpected roots, and unsafe/pre-existing destinations without changing checkout content.
- Accept the two reviewed root metadata files but do not copy them into the checkout.
- Copy the app's file permission bits so executable bundle files retain their build behavior.
- Verify that the promoted `Payload/YouTube.app/Info.plist` is byte-identical to the validated manifest and that the workflow passes this exact directory to `make`.
- Run Rust formatting, strict Clippy, Rust regressions, workflow validation, and exact-head CI. Record any missing platform/device evidence honestly.
