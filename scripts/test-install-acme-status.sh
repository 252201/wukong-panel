#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FUNCTION_BODY=$(awk '
  /^accept_acme_issue_status\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$ROOT/install.sh")
[ -n "$FUNCTION_BODY" ] || { echo "accept_acme_issue_status not found" >&2; exit 1; }

run_case() {
  status=$1
  expected_code=$2
  expected_text=$3
  code=0
  output=$(
    {
      eval "$FUNCTION_BODY"
      info() { printf 'INFO:%s\n' "$*"; }
      die() { printf 'DIE:%s\n' "$*" >&2; exit 64; }
      accept_acme_issue_status "$status"
    } 2>&1
  ) || code=$?
  [ "$code" -eq "$expected_code" ] || {
    printf 'status %s: expected exit %s, got %s\n%s\n' "$status" "$expected_code" "$code" "$output" >&2
    exit 1
  }
  if [ -n "$expected_text" ]; then
    printf '%s\n' "$output" | grep -F "$expected_text" >/dev/null || {
      printf 'status %s: missing output %s\n%s\n' "$status" "$expected_text" "$output" >&2
      exit 1
    }
  fi
}

run_case 0 0 ""
run_case 2 0 "跳过重复签发并继续安装"
run_case 1 64 "证书申请失败"
run_case 99 64 "返回码 99"
echo "acme issue status handling: ok"
