#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FUNCTION_BODY=$(awk '
  /^resolve_auto_action\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$ROOT/install.sh")
[ -n "$FUNCTION_BODY" ] || { echo "resolve_auto_action not found" >&2; exit 1; }
eval "$FUNCTION_BODY"

assert_action() {
  expected=$1
  installed=$2
  reconfigure=$3
  actual=$(resolve_auto_action "$installed" "$reconfigure")
  [ "$actual" = "$expected" ] || {
    printf 'expected %s, got %s (installed=%s reconfigure=%s)\n' "$expected" "$actual" "$installed" "$reconfigure" >&2
    exit 1
  }
}

assert_action install false false
assert_action update true false
assert_action install true true
echo "installer action resolution: ok"
