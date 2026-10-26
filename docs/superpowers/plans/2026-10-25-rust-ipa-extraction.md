# Rust IPA validation and extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run IPA validation and safe extraction through the existing Rust build-inputs project while keeping archive contents outside the source checkout until validation succeeds.

**Architecture:** Extend the Rust `ipa` command to stream a bounded HTTPS download, validate the digest and entire ZIP, preflight disk space, extract only the allowed app bundle into a fresh staging directory, then copy it to an absent Theos `Payload` destination. The workflow owns only the temporary-directory lifecycle and invokes Rust for download and preparation. Rust tests own the transfer, archive, space-policy, and workflow regressions.

**Tech Stack:** Rust 2021, existing `zip 8.6.0`, `plist`, `sha2`, `url`, and `libc` for Unix disk-space queries; GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-25-rust-ipa-extraction-design.md`

## Global Constraints
- New executable code and tests are Rust.
- Preserve the current URL, SHA-256, archive validation, metadata allowlist, version, and Theos behavior.
- Extract to a fresh directory under runner temp; copy only `Payload/YouTube.app` into an absent `main/Payload`.
- Enforce a 4 GiB transfer ceiling and retain 4 GiB of available space; the per-attempt ceiling is lowered to available space above that reserve.
- Ignore `Content-Length`, never write an over-limit byte, and remove partial transfers before retrying or failing.
- Before extraction, require space for the staged app and promoted copy plus the 4 GiB reserve, accounting for whether both destinations share a filesystem.
- Retain HTTPS-only redirects, 600-second per-attempt timeout, and two retries.
- Reuse the existing strict URL validator, provide the URL through a private curl config pipe, and disable ambient curl configuration.
- Keep operator-supplied digest provenance limits and separate issue #58 scope explicit.
- Do not claim macOS/Theos, signing, installation, or device validation without authorized evidence.

## Review Focus
- Valid app files preserve executable permission bits — integration test checks the copied file mode on Unix.
- Invalid root, traversal, symlink, FIFO, duplicate entry, and checksum inputs fail before checkout changes — Rust integration and unit tests.
- Allowed root metadata is accepted but never copied into `main/Payload` — integration test.
- Existing or symlinked `main/Payload` is never overwritten — integration test.
- Workflow invokes Rust extraction after secure download and does not invoke archive extraction commands — Rust workflow-policy test and exact-head CI.

---

### Task 1: Rust IPA prepare command

**Files:**
- Modify: `rust/build-inputs/src/bin/ipa.rs`
- Create: `rust/build-inputs/tests/ipa_prepare.rs`

**Interfaces:**
- Add `prepare(path: &Path, expected: &str, staging_root: &Path, payload_destination: &Path) -> Result<String, String>`.
- CLI accepts paired `--staging-dir` and `--payload-destination` arguments; when present, it prepares the bundle and prints the validated version.

- [x] Write the integration test for a valid synthetic IPA with an app file, executable mode, and allowed root metadata; assert version, staged app, copied app, and no root metadata under checkout.
- [x] Run the new integration test against the current CLI and confirm it fails specifically because preparation arguments are not supported.
- [x] Add negative integration cases for an unexpected member and pre-existing destination; assert the checkout marker and destination contents remain unchanged.
- [x] Implement full validation before creating staging or destination paths; reject existing paths without following symlinks; extract only the app subtree; preserve safe permission bits; copy only the staged app bundle.
- [x] Run focused Rust tests, then the complete Cargo suite.

### Task 2: Rust-only regression and workflow coverage

**Files:**
- Modify: `rust/build-inputs/src/main.rs`
- Modify: `rust/build-inputs/src/bin/ipa.rs`
- Create: `rust/build-inputs/tests/workflow_policy.rs`
- Modify: `.github/workflows/buildapp.yml`
- Remove after equivalent Rust coverage: `scripts/build_checks.py`, `tests/test_build_checks.py`, `tests/test_workflow_policy.py`

**Interfaces:**
- Reuse the Rust input validator and IPA command from Task 1.
- Workflow keeps HTTPS-only `curl`, runner-temp staging and trap cleanup; Rust performs ZIP validation, extraction and app promotion.

- [x] Port Python input URL edge cases to literal expected results in Rust tests; retain the existing input and IPA rejection cases.
- [x] Add Rust workflow-policy coverage for manual opt-in, validate-before-build, least-privilege publish separation, pinned actions, secure redirects, and the Rust prepare command.
- [x] Update the workflow to call Rust preparation and remove Python test execution, `unzip`, `cp -R`, and redundant shell path checks.
- [x] Remove the superseded Python validator/tests only after equivalent Rust coverage exists; remove Python differential invocations from Rust tests.
- [x] Run Rust tests, formatting, strict Clippy, and workflow shell/action validation.

### Task 3: Bounded download and disk preflight

**Files:**
- Create: `rust/build-inputs/Cargo.lock`
- Modify: `rust/build-inputs/Cargo.toml`
- Modify: `rust/build-inputs/src/bin/ipa.rs`
- Modify: `rust/build-inputs/src/main.rs`
- Create: `rust/build-inputs/src/lib.rs`
- Modify: `.github/workflows/buildapp.yml`
- Modify: `rust/build-inputs/tests/workflow_policy.rs`

**Interfaces:**
- Add an `ipa download` subcommand that streams `curl` output through Rust to a newly created runner-temp file.
- Share the existing strict public HTTPS URL policy between input validation and the downloader.
- Calculate each attempt's byte ceiling as `min(4 GiB, currently available bytes - 4 GiB reserve)`; fail if no space remains above the reserve.
- Return app-bundle expansion size from full archive verification and check the current destination-volume space before creating either output.

- [x] Add Rust tests for exact-cap success, over-cap rejection without writing the overflow byte, dynamic-cap/reserve boundaries, partial-file cleanup, retries, HTTPS policy, and shared/separate-volume extraction preflight.
- [ ] Run those focused tests and confirm the new transfer and preflight expectations fail before implementation. Local execution currently stops before compilation because this Windows machine lacks `link.exe`; use exact-head CI for execution.
- [x] Implement the Rust streamed transfer with HTTPS-only protocols and redirects, a 600-second timeout, two retries, fresh partial files, and generic URL-safe errors.
- [x] Implement fail-closed free-space queries on macOS and Linux and preflight both output volumes before extraction.
- [x] Replace workflow `curl --output` with the Rust download subcommand and update Rust workflow-policy coverage.
- [ ] Run focused and full Rust suites, formatting, strict Clippy, shell/action validation, and exact-head CI.

### Task 4: Review and exact-head verification

**Files:**
- Modify: `README.md` only if the existing build-isolation explanation needs correction.
- Modify: existing PR #14 body and RustyNuts #48 tracker after code and CI are final.

- [ ] Inspect the final diff and ensure only IPA isolation code, workflow, and regression files plus this plan/spec changed.
- [x] Run exact-head Linux source CI and read every job result. The repository does not configure Windows CI; local Windows compilation remains unavailable because `link.exe` is absent.
- [ ] Refresh PR #14, issue #48, reviews, branch head, and CI immediately before updating their GitHub descriptions.
- [x] Keep PR #14 Draft and issue #48 open while macOS/Theos compatibility and independent security review are still missing.
- [ ] Record the exact head, CI runs, and remaining external validation in PR #14 and RustyNuts #48.
