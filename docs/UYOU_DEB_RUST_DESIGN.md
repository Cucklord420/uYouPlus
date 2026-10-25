# Proposed Rust port: uYou Debian authentication and extraction

**Status:** Design proposal; implementation is gated on the user approving this design.

**Scope:** Cucklord420/uYouPlus PR #16, branch `fix/debian-ar-extraction-on-pr13-20261022`. Reviewed implementation head: `0bd2ecee9c40e0d720cd400ec56a340793667e9f`; this design document is on the same branch.

## Problem and policy

PR #16 addresses a real supply-chain and archive-format gap: a versioned HTTPS URL does not authenticate the downloaded Debian package, and a Debian `.deb` is an outer `ar` archive rather than a TAR file. The current PR adds Python validators, an extraction script, and Python tests. The repository's current `AGENTS.md` and Toe-Tickling Guidebook v1.2.4 require new executable code and tests to be Rust.

The port must preserve the fail-closed digest gate, bounded download, correct Debian extraction, staged payload validation, replacement rollback, and PR #15's transferred safeguards. It must not invent or supply a vendor digest.

## Proposed approach

Add a `uyou-deb` Rust binary to the existing `rust/build-inputs` Cargo package. Keep the package's current Rust 2021 edition and use its existing `sha2` dependency. Avoid adding a new runtime dependency unless implementation proves one is needed.

Keep Debian extraction in the existing `dpkg-deb` utility. Rust will invoke it directly with argument arrays (no shell parsing) and own validation, download orchestration, staging, and promotion. This avoids reimplementing Debian archive semantics while moving the new decision-making and executable logic into Rust.

The binary will expose three operations:

- `validate`: read the build's version and expected digest as environment data; validate the required 64-hex SHA-256 and 1–40 character version before any download, cache use, extraction, or Make invocation.
- `ensure`: accept a fixed build directory plus the version and expected digest. Validate the version before constructing any path or URL; construct the cache filename and fixed HTTPS release URL in Rust. Recheck any cached package; otherwise download to a unique temporary file beside the cache; enforce HTTPS-only redirects, bounded redirects/time/size, HTTP failure handling, and retries; validate Debian `ar` magic, regular-file type, size cap, and SHA-256; then promote without overwriting a concurrently-created cache file. If a competing cache file appears, accept it only after independently verifying it against the same expected digest.
- `extract`: accept the fixed build directory, version, and digest; derive the cache path only after validating the version, reverify the package, invoke `dpkg-deb --extract` into a new empty staging directory, validate the required dylib and bundle inside that staged tree, and only then replace the prior `Library` tree. Keep the current backup-and-restore behavior if promotion fails; never let stale files satisfy staged-payload checks.

For non-jailbroken builds, the Makefile will begin with a guard that refuses to proceed unless `UYOU_DEB_INPUTS_VALIDATED=1` is present. The guard must appear before any reference to `UYOU_VERSION` or any included Theos makefile. The workflow and documented local build command will run Rust `validate` first, then set this marker only for the subsequent Make invocation. This prevents GNU Make from expanding attacker-controlled Make functions before Rust rejects the input. GNU Make recursively expands variable values when referenced; see the [official manual on recursive assignment](https://www.gnu.org/software/make/manual/html_node/Recursive-Assignment.html). Recipes will quote shell environment expansions (for example, `--version "$$UYOU_VERSION"`) and will not interpolate `$(UYOU_VERSION)` into a file path, URL, or shell fragment. Rust validates again inside `ensure` and `extract`, and constructs the cache filename and URL only from validated data.

The guard and digest validation apply only when `JAILBROKEN` is not `1`. The existing jailbroken path does not fetch or extract a uYou Debian package and must keep working without a Debian digest or validation marker. Preserve its existing localization packaging behavior.

Update `docs/UYOU_PACKAGE_INTEGRITY.md` to document the Rust entry points and safe local invocation sequence while retaining the independent-digest warning. Existing Python tests for the pre-existing IPA-input behavior remain in place; the new Python uYou scripts and three uYou-specific Python test modules will be removed only after their behavior is covered by Rust tests.

The existing crate has edition 2021, no `rust-toolchain.toml`, and no `Cargo.lock` on the reviewed branch. Implementation will confirm the repository's lockfile/reproducibility policy before changing dependency state. It will not add dependencies merely to make this port easier.

## Regression coverage to preserve in Rust

Rust unit and integration tests will cover:

- Valid and invalid digests, malformed versions, missing files, directories and symlinks, Debian `ar` magic, empty and oversized inputs, digest mismatch, and symlinked package parents.
- In a non-jailbroken Make invocation, a value such as `UYOU_VERSION='$(shell touch marker)'` is rejected by the top-of-file guard before Make evaluates it; the marker remains absent. Verify the Rust preflight precedes the marker-setting Make call.
- The jailbroken `before-package` path still works without `UYOU_DEB_INPUTS_VALIDATED` or `UYOU_DEB_SHA256`, and does not fetch or extract a `.deb`.
- Shell metacharacters and command-substitution-looking version values are treated only as data by Rust and rejected before path construction or downloader invocation.
- Rejection of HTTP error bodies and failed downloads; no partial cache publication or leftover temporary file.
- A digest-matching synthetic download is verified before cache promotion and extraction.
- Synthetic `.deb` construction with `dpkg-deb` (when available), including required files, missing-payload rejection when old files exist, successful replacement of stale extras, and failure preservation of the previous payload.
- An injected failure at the new-`Library` promotion step restores the prior backed-up `Library` tree.
- Rust tests inspect the workflow and Makefile to ensure the guard precedes any version reference and Theos include for non-jailbroken builds, both paths delegate to the Rust binary, validation precedes Make and package consumption, and no unvalidated version is expanded into a shell path.
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
