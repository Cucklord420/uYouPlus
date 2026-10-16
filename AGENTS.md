# Agent instructions for uYouPlus

Before making substantive changes, read the complete current [canonical guidebook](https://github.com/Cucklord420/Toe-Tickling/blob/main/GUIDEBOOK.md) and its [agent entry point](https://github.com/Cucklord420/Toe-Tickling/blob/main/AGENTS.md). Apply them within the actual instruction hierarchy; this repository is not permission to access private information or bypass other controls.

Project-specific boundaries:

- This is a derivative iOS/Theos project. Preserve existing upstream code, attribution, third-party licenses, submodules, and compatibility. Do not relicense inherited components or distribute proprietary YouTube IPAs.
- All **newly authored executable code and tests** must be Rust under guidebook ENG-001. Preserve inherited non-Rust implementations until replacement behavior has been verified against the originals; do not force a mechanical Rust rewrite of platform-specific build glue.
- Before changing build inputs or artifact generation, inspect `build.sh`, `.github/workflows/buildapp.yml`, `.github/workflows/validate.yml`, `rust/build-inputs/`, and existing tests. Validate security boundaries, hashes, paths, dependencies, and failure handling. Keep build credentials least-privileged.
- Do not commit decrypted IPAs, copyrighted payloads, signing identities, credentials, or personal/device data. Validate only authorized synthetic inputs in CI.
- Prefer isolated pull requests and meaningful parity checks. Report whether tests actually ran, and do not claim installation or device testing without evidence.

The guidebook is maintained separately and changes over time; re-read its current reviewed default branch when starting a new task instead of assuming that this entry point is a full copy.
