# Proposed Rust port: uYou Debian authentication and extraction

**Status:** Design proposal; implementation is gated on the user approving this design.

**Scope:** Cucklord420/uYouPlus PR #16, branch `fix/debian-ar-extraction-on-pr13-20261022`. Reviewed PR head: `0bd2ecee9c40e0d720cd400ec56a340793667e9f`.

## Problem and policy

PR #16 closes a real supply-chain and archive-format gap: a versioned HTTPS URL does not authenticate the downloaded Debian package, and a Debian `.deb` is an outer `ar` archive rather than a TAR file. The current PR adds Python validators, an extraction script, and Python tests. The repository's current `AGENTS.md` and Toe-Tickling Guidebook v1.2.4 require new executable code and tests to be Rust.

The port must preserve the existing fail-closed digest gate, bounded download, correct Debian extraction, staged payload validation, replacement rollback, and PR #15's transferred safeguards. It must not invent or supply a vendor digest.

## Proposed approach

Add a `uyou-deb` Rust binary to the existing `rust/build-inputs` Cargo package. Keep the package's current Rust 2021 edition and use its existing `sha2` dependency. Avoid adding a new runtime dependency unless implementation proves one is needed.

Keep the mature Debian extraction implementation in the already-installed `dpkg-deb` utility. Rust will invoke it directly with argument arrays (no shell parsing), and will own validation, download orchestration, staging, and promotion. This avoids reimplementing Debian archive semantics while moving the new decision-making and executable logic into Rust.

The binary will expose three operations:

- `validate`: validate the required 64-hex SHA-256 input and the 1–40 character version format before any download, cache use, or extraction.
- `ensure`: validate the expected digest and version; recheck any cached package; otherwise download from the fixed HTTPS release URL to a unique temporary file beside the cache; enforce HTTPS-only redirects, bounded redirects/time/size, HTTP failure handling, and retries; validate the Debian `ar` magic, regular-file type, size cap, and SHA-256; then promote without overwriting a concurrently-created cache file. If a competing cache file appears, accept it only after independently verifying it against the same expected digest.
- `extract`: reverify the package, invoke `dpkg-deb --extract` into a new empty staging directory, validate the required dylib and bundle inside that staged tree, and only then replace the prior `Library` tree. Keep the current backup-and-restore behavior if promotion fails; never let stale files satisfy staged-payload checks.

The Makefile will delegate these operations to `cargo run --manifest-path rust/build-inputs/Cargo.toml --bin uyou-deb`. The workflow will invoke the same Rust validator and test suite. Existing Python tests for the pre-existing IPA-input behavior remain in place; the new Python uYou scripts and three uYou-specific Python test modules will be removed only after their behavior is covered by Rust tests. Update `docs/UYOU_PACKAGE_INTEGRITY.md` to describe the Rust entry points and retain the independent-digest warning.

The existing crate has edition 2021, no `rust-toolchain.toml`, and no `Cargo.lock` on the reviewed branch. Implementation will confirm the repository's lockfile/reproducibility policy before changing dependency state. It will not add dependencies merely to make this port easier.

## Regression coverage to preserve in Rust

Rust unit and integration tests will cover:

- Valid and invalid digests, malformed versions, missing files, directories and symlinks, Debian `ar` magic, empty and oversized inputs, digest mismatch, and symlinked package parents.
- Rejection of HTTP error bodies and failed downloads; no partial cache publication or leftover temporary file.
- A digest-matching synthetic download is verified before cache promotion and extraction.
- Synthetic `.deb` construction with `dpkg-deb` (when available), including required files, missing-payload rejection when old files exist, successful replacement of stale extras, and failure preservation of the previous payload.
- Rust tests that inspect the workflow and Makefile to ensure both delegate to the Rust binary and that validation precedes package consumption.
- A no-clobber cache-promotion regression for a destination that appears during download.

Network behavior will be tested offline through Rust-injected command execution, not through a shell or Python fake executable. Synthetic fixtures will contain fictional bytes only. The Debian integration test may skip on a runner without `dpkg-deb`; the dedicated Ubuntu extraction workflow and macOS build runner must exercise the relevant path.

## Alternatives considered

1. **Implement a complete Debian `ar`/TAR extractor in Rust.** Rejected for this change: it duplicates package-format and metadata handling already provided by `dpkg-deb`, increases parser and path-safety surface, and is unnecessary to fix the demonstrated defect.
2. **Keep Python and exempt these files from the Rust rule.** Rejected because current repository instructions explicitly cover validators, automation, and tests.
3. **Keep the shell download and move only hashing/extraction to Rust.** Rejected because the new Makefile recipe would continue to own security-sensitive download, temporary-file, and promotion behavior outside the mandated implementation language.

## Boundaries and unresolved evidence

This design does not establish an authentic digest for any particular upstream uYou release, prove the third-party package is safe, establish redistribution rights, or demonstrate a real macOS/Theos build or device installation. Do not derive the expected digest from the same downloaded file. Keep PR #16 Draft and unmerged until its independent vendor-digest provenance, review, and required compatibility evidence are resolved. No proprietary IPA or upstream package bytes will be added to the repository.

## Rollback

If implementation or compatibility evidence fails, revert the Rust binary integration and restore the prior reviewed branch state. A rollback also removes this proposed authentication and extraction protection, so the P1 supply-chain gap must remain tracked and open. Do not publish a release or perform a deployment as part of the port.
