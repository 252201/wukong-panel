#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FUNCTION_BODY=$(awk '
  /^singbox_expected_sha256\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$ROOT/install.sh")
[ -n "$FUNCTION_BODY" ] || { echo "singbox_expected_sha256 not found" >&2; exit 1; }
[ "$(sed -n 's/^SINGBOX_VERSION="\([^"]*\)"/\1/p' "$ROOT/install.sh")" = "1.13.14" ]
eval "$FUNCTION_BODY"

[ "$(singbox_expected_sha256 1.11.15 amd64)" = "950af37eb2d7e55dddae34a18411cd617303fd99d2dc75bc76b6dd9fcd97d9c5" ]
[ "$(singbox_expected_sha256 1.11.15 arm64)" = "20a6a9cd259a95411599f811a5066513a98db63705a51121252ad27daf96c029" ]
[ "$(singbox_expected_sha256 1.13.14 amd64)" = "f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697" ]
[ "$(singbox_expected_sha256 1.13.14 arm64)" = "4742df6a4314e8ecc41736849fca6d73b8f9e91b6e8b06ee794ff17ba180579e" ]
if singbox_expected_sha256 9.9.9 amd64 >/dev/null 2>&1; then
  echo "unsupported sing-box version accepted" >&2
  exit 1
fi

for function_name in sha256_file verify_singbox_backup; do
  body=$(awk -v name="$function_name" '
    $0 ~ "^" name "\\(\\)" { capture = 1 }
    capture { print }
    capture && /^}/ { exit }
  ' "$ROOT/install.sh")
  [ -n "$body" ] || { echo "$function_name not found" >&2; exit 1; }
  eval "$body"
done
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT INT TERM
printf 'safe backup\n' >"$test_dir/sing-box"
printf '%s  sing-box\n' "$(sha256_file "$test_dir/sing-box")" >"$test_dir/SHA256SUMS"
verify_singbox_backup "$test_dir"
printf 'tampered\n' >>"$test_dir/sing-box"
if verify_singbox_backup "$test_dir"; then
  echo "tampered backup accepted" >&2
  exit 1
fi
echo "sing-box verified version manifest: ok"
