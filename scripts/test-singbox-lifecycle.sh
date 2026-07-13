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

for function_name in sha256_file singbox_version_of ensure_singbox_for_install install_singbox_configs restore_singbox_configs backup_singbox verify_singbox_backup restore_singbox_service_definitions restore_singbox_after_uninstall_failure remove_singbox_managed_files singbox_binary_is_running uninstall_singbox persist_singbox_transaction clear_singbox_transaction rollback_singbox_transaction; do
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

transaction_dir="$test_dir/transaction"
backup_dir="$test_dir/backup"
live_dir="$test_dir/live"
mkdir -p "$backup_dir/configs" "$live_dir/configs"
printf '#!/bin/sh\necho old\n' >"$backup_dir/sing-box"
chmod 0755 "$backup_dir/sing-box"
printf 'old config\n' >"$backup_dir/configs/node.json"
printf 'systemd:sing-box-node.service\n' >"$backup_dir/active-services"
{
  printf '%s  sing-box\n' "$(sha256_file "$backup_dir/sing-box")"
  printf '%s  configs/node.json\n' "$(sha256_file "$backup_dir/configs/node.json")"
} >"$backup_dir/SHA256SUMS"
printf '#!/bin/sh\necho new\n' >"$live_dir/sing-box"
chmod 0755 "$live_dir/sing-box"
printf 'new config\n' >"$live_dir/configs/node.json"

SINGBOX_TRANSACTION_ROOT="$transaction_dir"
SINGBOX_TRANSACTION_ACTIVE=false
singbox_config_dir() { printf '%s' "$live_dir/configs"; }
stop_singbox_services() { [ -s "$1" ]; }
start_singbox_services() { [ -s "$1" ]; }
check_singbox_configs() { [ -x "$1" ]; }
singbox_version_of() { printf '1.10.7'; }
warn() { :; }
info() { :; }

persist_singbox_transaction "$backup_dir" "$live_dir/sing-box"
[ -r "$transaction_dir/backup-path" ]
rollback_singbox_transaction
[ ! -e "$transaction_dir" ]
grep -q '^echo old$' "$live_dir/sing-box"
grep -q '^old config$' "$live_dir/configs/node.json"
[ "$SINGBOX_TRANSACTION_ACTIVE" = false ]
grep -q '未检测到正在运行的 sing-box 服务，已拒绝更新' "$ROOT/install.sh"
grep -q "trap 'exit 129' HUP" "$ROOT/install.sh"
grep -q '未完成事务已恢复；为便于确认节点连通性，本次不再继续升级' "$ROOT/install.sh"

bootstrap_dir="$test_dir/bootstrap"
mkdir -p "$bootstrap_dir/configs"
singbox_version_of() { "$1" version 2>/dev/null | sed -n 's/^sing-box version //p' | head -1; }
SINGBOX_VERSION=1.13.14
SINGBOX_RUNTIME_BIN=""
SINGBOX_RUNTIME_CONFIG_DIR=""
singbox_binary_path() { printf '%s' "$bootstrap_dir/configs/sing-box"; }
singbox_config_dir() { printf '%s' "$bootstrap_dir/configs"; }
download_singbox_binary() {
  SINGBOX_CANDIDATE="$bootstrap_dir/candidate"
  printf '#!/bin/sh\n[ "$1" = version ] && echo "sing-box version 1.13.14"\n' >"$SINGBOX_CANDIDATE"
  chmod 0755 "$SINGBOX_CANDIDATE"
}
info() { :; }
die() { printf '%s\n' "$*" >&2; return 1; }
ensure_singbox_for_install
[ "$(singbox_version_of "$bootstrap_dir/configs/sing-box")" = 1.13.14 ]
[ "$SINGBOX_RUNTIME_BIN" = "$bootstrap_dir/configs/sing-box" ]
download_singbox_binary() { return 99; }
ensure_singbox_for_install

uninstall_dir="$test_dir/uninstall"
mkdir -p "$uninstall_dir/configs" "$uninstall_dir/tmp" "$uninstall_dir/backups"
printf '#!/bin/sh\n[ "$1" = version ] && echo "sing-box version 1.13.14"\n[ "$1" = check ] && exit 0\n' >"$uninstall_dir/configs/sing-box"
chmod 0755 "$uninstall_dir/configs/sing-box"
printf '{"inbounds":[]}\n' >"$uninstall_dir/configs/node.json"
printf 'keep certificate\n' >"$uninstall_dir/configs/cert.pem"
TMP_DIR="$uninstall_dir/tmp"
SINGBOX_BACKUP_ROOT="$uninstall_dir/backups"
SINGBOX_TRANSACTION_ROOT="$uninstall_dir/transaction"
singbox_binary_path() { printf '%s' "$uninstall_dir/configs/sing-box"; }
singbox_config_dir() { printf '%s' "$uninstall_dir/configs"; }
capture_active_singbox_services() { : >"$1"; }
capture_managed_singbox_services() { : >"$1"; }
stop_singbox_services() { return 0; }
start_singbox_services() { return 0; }
remove_singbox_service_definitions() { return 0; }
using_systemd() { return 1; }
check_singbox_configs() { "$1" check -c "$2/node.json"; }
uninstall_singbox
[ ! -e "$uninstall_dir/configs/sing-box" ]
[ ! -e "$uninstall_dir/configs/node.json" ]
[ -f "$uninstall_dir/configs/cert.pem" ]
uninstall_backup=$(find "$uninstall_dir/backups" -mindepth 1 -maxdepth 1 -type d | head -1)
[ -n "$uninstall_backup" ]
verify_singbox_backup "$uninstall_backup"
[ -f "$uninstall_backup/active-services" ]
[ -f "$uninstall_backup/managed-services" ]
grep -q 'node.json' "$uninstall_backup/SHA256SUMS"
check_singbox_configs() { "$1" check -c "$(singbox_config_dir)/node.json"; }
restore_singbox_after_uninstall_failure "$uninstall_backup" "$uninstall_dir/configs/sing-box"
[ "$(singbox_version_of "$uninstall_dir/configs/sing-box")" = 1.13.14 ]
grep -q 'inbounds' "$uninstall_dir/configs/node.json"
grep -q -- '--uninstall-sing-box' "$ROOT/install.sh"
grep -q 'ensure_singbox_for_install' "$ROOT/install.sh"
echo "sing-box verified version manifest: ok"
