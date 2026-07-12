#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FUNCTION_BODY=$(awk '
  /^singbox_expected_sha256\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$ROOT/install.sh")
[ -n "$FUNCTION_BODY" ] || { echo "singbox_expected_sha256 not found" >&2; exit 1; }
eval "$FUNCTION_BODY"

[ "$(singbox_expected_sha256 1.11.15 amd64)" = "950af37eb2d7e55dddae34a18411cd617303fd99d2dc75bc76b6dd9fcd97d9c5" ]
[ "$(singbox_expected_sha256 1.11.15 arm64)" = "20a6a9cd259a95411599f811a5066513a98db63705a51121252ad27daf96c029" ]
if singbox_expected_sha256 9.9.9 amd64 >/dev/null 2>&1; then
  echo "unsupported sing-box version accepted" >&2
  exit 1
fi
echo "sing-box verified version manifest: ok"
