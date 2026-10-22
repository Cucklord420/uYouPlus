#!/usr/bin/env bash
# Fail-closed verification for the downloaded third-party uYou Debian package.
# Expected digest must come from an independently reviewed source.
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo 'Usage: fetch-verified-uyou-deb VERSION DESTINATION EXPECTED_SHA256' >&2
  exit 2
fi
version="$1"
destination="$2"
expected="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"

if ! [[ "$version" =~ ^[0-9]+(\.[0-9]+){1,4}$ ]]; then
  echo 'Invalid uYou version' >&2
  exit 2
fi
if ! [[ "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'A reviewed, 64-character uYou SHA-256 digest is required' >&2
  exit 2
fi
if [[ -L "$destination" ]]; then
  echo 'Refusing symlinked uYou package destination' >&2
  exit 1
fi

digest_file() {
  local value
  if command -v shasum >/dev/null 2>&1; then
    value="$(shasum -a 256 -- "$1")" || return 1
  elif command -v sha256sum >/dev/null 2>&1; then
    value="$(sha256sum -- "$1")" || return 1
  else
    echo 'SHA-256 utility unavailable' >&2
    return 1
  fi
  printf '%s\n' "${value%% *}" | tr '[:upper:]' '[:lower:]'
}
verify_file() {
  local candidate="$1"
  if [[ ! -f "$candidate" || -L "$candidate" || ! -s "$candidate" ]]; then
    echo 'uYou package is missing, empty, or not a regular file' >&2
    return 1
  fi
  local size
  size="$(wc -c < "$candidate")" || return 1
  if (( size > 268435456 )); then
    echo 'uYou package exceeds 256 MiB safety cap' >&2
    return 1
  fi
  local actual
  actual="$(digest_file "$candidate")" || return 1
  if [[ "$actual" != "$expected" ]]; then
    echo 'uYou package SHA-256 mismatch; refusing extraction' >&2
    return 1
  fi
}

# An existing cached package is untrusted until its digest is reverified.
if [[ -e "$destination" ]]; then
  verify_file "$destination"
  exit 0
fi

parent="$(dirname -- "$destination")"
mkdir -p -- "$parent"
if [[ -L "$parent" ]]; then
  echo 'Refusing symlinked uYou destination directory' >&2
  exit 1
fi
temporary="$(mktemp "${destination}.part.XXXXXXXX")"
trap 'rm -f -- "$temporary"' EXIT
url="https://repo.miro92.com/debs/com.miro.uyou_${version}_iphoneos-arm.deb"
curl --fail --silent --show-error --location --max-redirs 3 \
  --proto '=https' --proto-redir '=https' \
  --connect-timeout 15 --max-time 180 --retry 2 \
  --output "$temporary" "$url"
verify_file "$temporary"
if [[ -e "$destination" || -L "$destination" ]]; then
  echo 'Package destination was created concurrently; refusing to overwrite' >&2
  exit 1
fi
mv -n -- "$temporary" "$destination"
# A race or failed publication must not be treated as success.
verify_file "$destination"
