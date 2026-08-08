#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

normalize_body=$(sed -n '/^firewall_normalize_ports()/,/^firewall_validate_ports()/ { /^firewall_validate_ports()/d; p; }' "$ROOT/install.sh")
[ -n "$normalize_body" ] || die "firewall_normalize_ports not found"
eval "$normalize_body"

expected_ports='22/tcp
9443/tcp
45080/udp'
actual_ports=$(firewall_normalize_ports '22/tcp,9443,45080/udp')
[ "$actual_ports" = "$expected_ports" ] || die "firewall port normalization failed"

if firewall_normalize_ports '0/tcp' >/dev/null 2>&1; then
  die "port zero was accepted"
fi
if firewall_normalize_ports '9443/sctp' >/dev/null 2>&1; then
  die "unsupported firewall protocol was accepted"
fi

grep -Fq -- '--firewall-mode MODE' "$ROOT/install.sh" || die "install firewall mode flag missing"
grep -Fq -- '--firewall-action MODE' "$ROOT/install.sh" || die "firewall action flag missing"
grep -Fq '或 firewall' "$ROOT/install.sh" || die "firewall action is not advertised"
grep -Fq -- '--firewall-open-all' "$ROOT/install.sh" || die "firewall open-all flag missing"
grep -Fq -- '--takeover-port-80' "$ROOT/install.sh" || die "port 80 takeover flag missing"
grep -Fq 'ca-certificates curl openssl nginx tcpdump tar iproute2' "$ROOT/install.sh" || die "apt/apk runtime dependency bootstrap missing"
grep -Fq 'ca-certificates curl openssl nginx tcpdump tar iproute shadow-utils' "$ROOT/install.sh" || die "dnf runtime dependency bootstrap missing"
grep -Fq 'install_download_tools' "$ROOT/install.sh" || die "update download dependency bootstrap missing"
grep -Fq 'restore_port80_services || true' "$ROOT/install.sh" || die "port 80 restore trap missing"
grep -Fq '纯净 VPS 如果没有预装 `curl`' "$ROOT/README.md" || die "curl bootstrap documentation missing"
grep -Fq -- '--takeover-port-80' "$ROOT/README.md" || die "port 80 documentation missing"
grep -Fq -- '--firewall-status' "$ROOT/README.md" || die "firewall documentation missing"
grep -Fq 'INSTALL_URL=' "$ROOT/bootstrap.sh" || die "bootstrap downloader missing"
grep -Fq 'apt-get install' "$ROOT/bootstrap.sh" || die "bootstrap apt fallback missing"
grep -Fq 'dnf install' "$ROOT/bootstrap.sh" || die "bootstrap dnf fallback missing"
grep -Fq 'apk add' "$ROOT/bootstrap.sh" || die "bootstrap apk fallback missing"

printf '%s\n' 'installer hardening: ok'
