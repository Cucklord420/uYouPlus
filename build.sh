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

make package THEOS_PACKAGE_SCHEME=rootless IPA="$PATHTOYT" FINALPACKAGE=1

# SHASUM
if [[ $? -eq 0 ]]; then
  open packages
  echo "SHASUM256: $(shasum -a 256 packages/*.ipa)"

else
  echo "Failed building uYouPlus"

fi
