#!/bin/sh
# Fetch only independently authenticated uYou bytes; never unpack here.
set -eu
if [ "$#" -gt 1 ]; then
  echo 'Usage: fetch_uyou_deb.sh [DESTINATION]' >&2
  exit 2
fi
version=${UYOU_VERSION:-}
digest=${UYOU_DEB_SHA256:-}
case "$version" in
  ''|*[!0-9.]*) echo 'Invalid uYou version' >&2; exit 1 ;;
esac
printf '%s\n' "$version" | grep -Eq '^[0-9]+(\.[0-9]+){1,4}$' || {
  echo 'Invalid uYou version' >&2
  exit 1
}
printf '%s\n' "$digest" | grep -Eq '^[0-9A-Fa-f]{64}$' || {
  echo 'An independently reviewed uYou SHA-256 is required' >&2
  exit 1
}
package=${1:-"Tweaks/uYou/com.miro.uyou_${version}_iphoneos-arm.deb"}
verify="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/verify_uyou_deb.py"
if [ -e "$package" ] || [ -L "$package" ]; then
  python3 "$verify" --file "$package" --sha256 "$digest"
  exit $?
fi
# Keep an incomplete or tampered response away from the final package path.
tmp=$(mktemp "${package}.part.XXXXXXXX")
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
url="https://repo.miro92.com/debs/com.miro.uyou_${version}_iphoneos-arm.deb"
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 180 --retry 2 \
  --output "$tmp" "$url"
python3 "$verify" --file "$tmp" --sha256 "$digest"
mv -f -- "$tmp" "$package"
trap - EXIT HUP INT TERM
