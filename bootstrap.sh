#!/bin/sh
set -eu

INSTALL_URL=${WUKONG_INSTALL_URL:-https://github.com/252201/wukong-panel/releases/latest/download/install.sh}

[ "$(id -u)" -eq 0 ] || {
  printf '%s\n' '请使用 root 或 sudo 执行 bootstrap.sh' >&2
  exit 1
}

if command -v curl >/dev/null 2>&1; then
  curl -fsSL --retry 3 "$INSTALL_URL" | sh -s -- "$@"
  exit 0
fi

if command -v wget >/dev/null 2>&1; then
  wget -qO- "$INSTALL_URL" | sh -s -- "$@"
  exit 0
fi

case "$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '"')" in
  debian|ubuntu)
    apt-get update -qq >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl >&2
    ;;
  rocky|almalinux|rhel|centos)
    dnf install -y -q ca-certificates curl >&2
    ;;
  alpine)
    apk add -q ca-certificates curl >&2
    ;;
  *)
    printf '%s\n' '找不到 curl 或 wget，且当前系统没有受支持的包管理器。请先安装 curl。' >&2
    exit 1
    ;;
esac

curl -fsSL --retry 3 "$INSTALL_URL" | sh -s -- "$@"
