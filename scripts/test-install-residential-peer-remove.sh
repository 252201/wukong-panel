#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

FUNCTION_BODY=$(awk '
  /^remove_residential_peer\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$ROOT/install.sh")
[ -n "$FUNCTION_BODY" ] || {
  echo "remove_residential_peer not found" >&2
  exit 1
}

printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'residential_peer_installed ||'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'wg-quick down "$peer_interface"'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'systemctl disable --now "wg-quick@$peer_interface.service"'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'rc-service "$peer_interface" stop'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'rc-update del "$peer_interface" default'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'ip link delete "$peer_interface"'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq '/etc/sysctl.d/99-wukong-exit.conf'

grep -Fq "grep -Eq '^Address[[:space:]]*=[[:space:]]*10\\.77\\.0\\.2/30" "$ROOT/install.sh"
grep -Fq "grep -Eq '^AllowedIPs[[:space:]]*=[[:space:]]*10\\.77\\.0\\.1/32" "$ROOT/install.sh"
grep -Fq -- '--remove-residential-peer' "$ROOT/install.sh"

echo "installer residential peer removal: ok"
