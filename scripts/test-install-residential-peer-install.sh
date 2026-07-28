#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

FUNCTION_BODY=$(awk '
  /^install_residential_peer\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$ROOT/install.sh")
[ -n "$FUNCTION_BODY" ] || {
  echo "install_residential_peer not found" >&2
  exit 1
}

printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'grep -Eq '\''^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]+$'\'''
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'grep -Eq '\''^[A-Za-z0-9+/]{43}=$'\'''
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'run_quiet apt-get update -qq'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'wireguard-tools iproute2 iptables'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'Address = 10.77.0.2/30'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'AllowedIPs = 10.77.0.1/32'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'sysctl -w net.ipv4.ip_forward=1'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'systemctl restart "wg-quick@$peer_interface.service"'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'rc-service "$peer_interface" restart'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq 'B_PUBLIC_KEY=%s'
printf '%s\n' "$FUNCTION_BODY" | grep -Fq -- '--remove-residential-peer'

grep -Fq -- '--install-residential-peer) ACTION=residential-peer-install' "$ROOT/install.sh"
grep -Fq -- '--residential-endpoint) RESIDENTIAL_ENDPOINT="$2"' "$ROOT/install.sh"
grep -Fq -- '--residential-public-key) RESIDENTIAL_PUBLIC_KEY="$2"' "$ROOT/install.sh"

echo "installer residential peer installation: ok"
