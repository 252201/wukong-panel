#!/bin/sh
set -eu
VERSION=${1:-0.1.0}
export GOTOOLCHAIN=go1.26.5
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/release"
cd "$ROOT"
rm -rf "$OUT"
mkdir -p "$OUT"

for arch in amd64 arm64; do
  echo "building linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o "$OUT/wukong-panel-linux-$arch" ./cmd/wukong-panel
done
cp "$ROOT/install.sh" "$ROOT/uninstall.sh" "$OUT/"
chmod 0755 "$OUT"/*
(cd "$OUT" && sha256sum wukong-panel-linux-* > SHA256SUMS)
echo "release artifacts: $OUT"
