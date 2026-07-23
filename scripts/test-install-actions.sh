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
[ "$(grep -c -- '--reset-password)' "$ROOT/install.sh")" -eq 1 ] || { echo "reset password flag missing" >&2; exit 1; }
grep -q -- '--start|--start-panel) ACTION=start' "$ROOT/install.sh" || { echo "start panel flag missing" >&2; exit 1; }
grep -q -- '--stop|--stop-panel) ACTION=stop' "$ROOT/install.sh" || { echo "stop panel flag missing" >&2; exit 1; }
grep -q '2|start) ACTION=start' "$ROOT/install.sh" || { echo "start panel menu action missing" >&2; exit 1; }
grep -q '3|stop) ACTION=stop' "$ROOT/install.sh" || { echo "stop panel menu action missing" >&2; exit 1; }
grep -q '7|reset-password) ACTION=reset-password' "$ROOT/install.sh" || { echo "reset password menu action missing" >&2; exit 1; }
grep -q '"$TMP_DIR/wukong-panel" reset-password --data-dir /var/lib/wukong-panel' "$ROOT/install.sh" || { echo "reset password command missing" >&2; exit 1; }
[ "$(grep -c 'checkpath --directory --owner root:wukong --mode 0750 /run/wukong-panel' "$ROOT/install.sh")" -eq 2 ] || {
  echo "OpenRC runtime directory hooks missing" >&2
  exit 1
}
[ "$(grep -c '^RuntimeDirectory=wukong-panel$' "$ROOT/install.sh")" -eq 1 ] || {
  echo "systemd runtime directory missing" >&2
  exit 1
}
grep -q '^RuntimeDirectoryMode=0750$' "$ROOT/install.sh" || {
  echo "systemd runtime directory mode missing" >&2
  exit 1
}
echo "installer action resolution: ok"
