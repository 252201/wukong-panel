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
grep -q -- '--install-residential-peer) ACTION=residential-peer-install' "$ROOT/install.sh" || { echo "residential peer install flag missing" >&2; exit 1; }
grep -q -- '--remove-residential-peer) ACTION=residential-peer-remove' "$ROOT/install.sh" || { echo "residential peer removal flag missing" >&2; exit 1; }
grep -q -- '--join-controller) JOIN_CONTROLLER=' "$ROOT/install.sh" || { echo "fleet controller join flag missing" >&2; exit 1; }
grep -q -- '--enrollment-token) ENROLLMENT_TOKEN=' "$ROOT/install.sh" || { echo "fleet enrollment token flag missing" >&2; exit 1; }
grep -q -- '--leave-controller) LEAVE_CONTROLLER=true' "$ROOT/install.sh" || { echo "fleet leave flag missing" >&2; exit 1; }
grep -q -- '--configure-subscription-domain) ACTION=subscription-domain' "$ROOT/install.sh" || { echo "subscription domain flag missing" >&2; exit 1; }
grep -q '/usr/local/bin/wukong-panel fleet leave' "$ROOT/install.sh" || { echo "fleet leave command missing" >&2; exit 1; }
grep -q '2|start) ACTION=start' "$ROOT/install.sh" || { echo "start panel menu action missing" >&2; exit 1; }
grep -q '3|stop) ACTION=stop' "$ROOT/install.sh" || { echo "stop panel menu action missing" >&2; exit 1; }
grep -q '7|reset-password) ACTION=reset-password' "$ROOT/install.sh" || { echo "reset password menu action missing" >&2; exit 1; }
grep -q '11|residential-peer-remove) ACTION=residential-peer-remove' "$ROOT/install.sh" || { echo "residential peer removal menu action missing" >&2; exit 1; }
grep -q '12|firewall) ACTION=firewall' "$ROOT/install.sh" || { echo "firewall menu action missing" >&2; exit 1; }
grep -q '13|subscription-domain) ACTION=subscription-domain' "$ROOT/install.sh" || { echo "subscription domain menu action missing" >&2; exit 1; }
grep -q '14|cancel) info "已取消"' "$ROOT/install.sh" || { echo "cancel menu action missing" >&2; exit 1; }
grep -q '请选择防火墙操作' "$ROOT/install.sh" || { echo "interactive firewall menu missing" >&2; exit 1; }
grep -q '5|all) FIREWALL_ACTION=all' "$ROOT/install.sh" || { echo "interactive open-all firewall action missing" >&2; exit 1; }
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
