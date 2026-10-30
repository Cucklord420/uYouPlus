#!/bin/bash
# To build, either place the IPA file in the project's root directory, or get the path to the IPA, then run `./build.sh`

script_path=${BASH_SOURCE[0]}
script_directory=${script_path%/*}
if [[ "$script_directory" == "$script_path" ]]; then
  script_directory=.
elif [[ -z "$script_directory" ]]; then
  script_directory=/
fi
script_directory=$(CDPATH= cd -- "$script_directory" && pwd)
if [[ -n "${UYOUPLUS_BUILD_BIN:-}" ]]; then
  exec "$UYOUPLUS_BUILD_BIN" local-build
fi
exec cargo run --quiet --manifest-path "$script_directory/rust/build-inputs/Cargo.toml" --bin uyouplus-inputs -- local-build
