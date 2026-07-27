#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

FUNCTION_BODY=$(awk '
  /^ensure_residential_exit_dependencies\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$ROOT/install.sh")
[ -n "$FUNCTION_BODY" ] || {
  echo "ensure_residential_exit_dependencies not found" >&2
  exit 1
}

printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'apt-get install -y -qq wireguard-tools iproute2'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'dnf install -y -q wireguard-tools iproute'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'apk add -q wireguard-tools iproute2'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'for dependency_binary in wg wg-quick ip'

UPDATE_CALL_LINE=$(grep -n '^  ensure_residential_exit_dependencies$' "$ROOT/install.sh" | head -1 | cut -d: -f1)
UPDATE_PANEL_LINE=$(grep -n '^  update_panel$' "$ROOT/install.sh" | head -1 | cut -d: -f1)
[ -n "$UPDATE_CALL_LINE" ] && [ "$UPDATE_CALL_LINE" -lt "$UPDATE_PANEL_LINE" ] || {
  echo "update must ensure residential dependencies before replacing the panel" >&2
  exit 1
}

INSTALL_CALL_LINE=$(grep -n '^ensure_residential_exit_dependencies$' "$ROOT/install.sh" | tail -1 | cut -d: -f1)
INSTALL_DIR_LINE=$(grep -n '^install -d -m 0755 /usr/local/bin' "$ROOT/install.sh" | head -1 | cut -d: -f1)
[ -n "$INSTALL_CALL_LINE" ] && [ "$INSTALL_CALL_LINE" -lt "$INSTALL_DIR_LINE" ] || {
  echo "install must ensure residential dependencies before writing panel files" >&2
  exit 1
}

echo "installer residential dependencies: ok"
