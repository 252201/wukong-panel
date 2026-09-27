#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

info() { :; }
warn() { :; }
UPDATE_BACKUP_RETENTION=3
WUKONG_UPDATE_BACKUP_ROOT="$TEMP_ROOT/backups"
mkdir -p "$WUKONG_UPDATE_BACKUP_ROOT"

prune_body=$(sed -n '/^prune_update_backups()/,/^}/p' "$ROOT/install.sh")
[ -n "$prune_body" ] || die "prune_update_backups not found"
eval "$prune_body"

for timestamp in 000001 000002 000003 000004 000005; do
  mkdir "$WUKONG_UPDATE_BACKUP_ROOT/update-20260927-$timestamp"
done
touch "$WUKONG_UPDATE_BACKUP_ROOT/update-20260927-000001/.rollback-required"
mkdir "$WUKONG_UPDATE_BACKUP_ROOT/update-backup-not-timestamped"

prune_update_backups

[ -d "$WUKONG_UPDATE_BACKUP_ROOT/update-20260927-000001" ] || die "rollback backup was removed"
[ -e "$WUKONG_UPDATE_BACKUP_ROOT/update-20260927-000001/.rollback-required" ] || die "rollback marker was removed"
[ ! -e "$WUKONG_UPDATE_BACKUP_ROOT/update-20260927-000002" ] || die "oldest successful update backup was not pruned"
for timestamp in 000003 000004 000005; do
  [ -d "$WUKONG_UPDATE_BACKUP_ROOT/update-20260927-$timestamp" ] || die "one of the three newest successful update backups was removed"
done
[ -d "$WUKONG_UPDATE_BACKUP_ROOT/update-backup-not-timestamped" ] || die "unmatched backup directory was removed"

marker_line=$(grep -nF ': > "$backup_dir/.rollback-required"' "$ROOT/install.sh" | cut -d: -f1)
stop_line=$(grep -nF '  stop_panel_services' "$ROOT/install.sh" | awk -F: '$1 > 1300 && $1 < 1450 { print $1; exit }')
[ -n "$marker_line" ] && [ -n "$stop_line" ] && [ "$marker_line" -lt "$stop_line" ] || die "rollback marker is not created before stopping services"
grep -Fq 'rm -f "$backup_dir/.rollback-required"' "$ROOT/install.sh" || die "successful update does not clear rollback marker"

printf '%s\n' 'update backup retention: ok'
