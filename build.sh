#!/bin/bash
# To build, either place the IPA file in the project's root directory, or get the path to the IPA, then run `./build.sh`

read -r -p $'\e[34m==> \e[1;39mPath to the decrypted YouTube.ipa or YouTube.app. If nothing is provided, any ipa/app in the project\'s root directory will be used: ' PATHTOYT

discover_root_input() {
    if [ -n "${UYOUPLUS_INPUTS_BIN:-}" ]; then
        "$UYOUPLUS_INPUTS_BIN" discover-root-input
    else
        cargo run --quiet --manifest-path rust/build-inputs/Cargo.toml --bin uyouplus-inputs -- discover-root-input
    fi
}

# Check if PATHTOYT is empty
if [ -z "$PATHTOYT" ]; then
    # The Rust helper writes exactly one native path followed by NUL.
    if ! IFS= read -r -d '' PATHTOYT < <(discover_root_input); then
        echo "❌ Error: Could not discover one root-level IPA/app candidate."
        exit 1
    fi
fi

# Mark the start of this build, so an old package cannot be mistaken for output.
build_marker=$(mktemp ./.uyou-build-start.XXXXXXXX) || {
  echo "Build output rejected: cannot create build-start marker"
  exit 1
}
trap 'rm -f -- "$build_marker"' EXIT

make package THEOS_PACKAGE_SCHEME=rootless IPA="$PATHTOYT" FINALPACKAGE=1
build_status=$?

if [[ $build_status -ne 0 ]]; then
  echo "Failed building uYouPlus"
  exit "$build_status"
fi

# A successful make alone does not prove it produced a release artifact.
shopt -s nullglob
artifacts=(packages/*.ipa)
shopt -u nullglob
if [[ ${#artifacts[@]} -ne 1 ]]; then
  echo "Build output rejected: expected exactly one IPA artifact"
  exit 1
fi

ipa="${artifacts[0]}"
if [[ ! -f "$ipa" || -L "$ipa" || ! -s "$ipa" || ! "$ipa" -nt "$build_marker" ]]; then
  echo "Build output rejected: IPA must be a new nonempty regular file"
  exit 1
fi

if ! checksum=$(shasum -a 256 "$ipa"); then
  echo "Build output rejected: SHA-256 calculation failed"
  exit 1
fi
if [[ ! "$checksum" =~ ^[[:xdigit:]]{64}[[:space:]][[:space:]] ]] || [[ "${checksum:66}" != "$ipa" ]]; then
  echo "Build output rejected: invalid SHA-256 output"
  exit 1
fi

printf 'SHA256: %s\n' "$checksum"
# Opening the output folder is a UI convenience, not a release-integrity gate.
open packages >/dev/null 2>&1 || true
