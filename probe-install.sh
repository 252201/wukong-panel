#!/bin/sh
set -eu

REPO=252201/wukong-panel
VERSION=latest
CONTROLLER=""
TOKEN=""
HOST_NAME=""
ACTION=install
CONFIG_DIR=/etc/wukong-probe
BIN=/usr/local/bin/wukong-probe

fail() { echo "[悟空探针] $*" >&2; exit 1; }
info() { echo "[悟空探针] $*"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --controller) [ "$#" -ge 2 ] || fail "缺少 --controller 值"; CONTROLLER=$2; shift 2 ;;
    --enrollment-token) [ "$#" -ge 2 ] || fail "缺少 --enrollment-token 值"; TOKEN=$2; shift 2 ;;
    --host-name) [ "$#" -ge 2 ] || fail "缺少 --host-name 值"; HOST_NAME=$2; shift 2 ;;
    --version) [ "$#" -ge 2 ] || fail "缺少 --version 值"; VERSION=$2; shift 2 ;;
    --update) ACTION=update; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    *) fail "未知参数: $1" ;;
  esac
done
[ "$(id -u)" -eq 0 ] || fail "请以 root 运行"
case "$VERSION" in latest|v[0-9]*) ;; *) fail "--version 必须是 latest 或 vX.Y.Z" ;; esac
case "$(uname -s)/$(uname -m)" in Linux/x86_64) ARCH=amd64 ;; Linux/aarch64|Linux/arm64) ARCH=arm64 ;; *) fail "仅支持 Linux amd64/arm64" ;; esac
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  MANAGER=systemd
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
  MANAGER=openrc
else
  fail "需要 systemd 或 OpenRC"
fi

if [ "$ACTION" = uninstall ]; then
  if [ "$MANAGER" = systemd ]; then
    systemctl disable --now wukong-probe.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/wukong-probe.service
    systemctl daemon-reload
  else
    rc-service wukong-probe stop >/dev/null 2>&1 || true
    rc-update del wukong-probe default >/dev/null 2>&1 || true
    rm -f /etc/init.d/wukong-probe
  fi
  rm -f "$BIN"
  rm -rf "$CONFIG_DIR"
  info "已卸载本机探针；请在中央控制台移除离线主机记录"
  exit 0
fi
if [ "$ACTION" = install ]; then
  [ -n "$CONTROLLER" ] && [ -n "$TOKEN" ] || fail "需要 --controller 与 --enrollment-token"
  [ ! -e "$CONFIG_DIR/config.json" ] || fail "探针已接入；更新请使用 --update"
else
  [ -r "$CONFIG_DIR/config.json" ] || fail "未检测到已接入的探针"
fi
command -v curl >/dev/null 2>&1 || fail "需要 curl；安装 curl 和 ca-certificates 后重试"
command -v sha256sum >/dev/null 2>&1 || fail "需要 sha256sum"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
BASE="https://github.com/$REPO/releases/$VERSION/download"
if [ "$VERSION" = latest ]; then BASE="https://github.com/$REPO/releases/latest/download"; fi
ASSET="wukong-probe-linux-$ARCH"
curl -fsSL --retry 3 "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS" || fail "无法下载校验清单"
curl -fsSL --retry 3 "$BASE/$ASSET" -o "$TMP/$ASSET" || fail "无法下载探针"
EXPECTED=$(awk -v asset="$ASSET" '$2 == asset { print $1 }' "$TMP/SHA256SUMS")
[ -n "$EXPECTED" ] || fail "校验清单缺少 $ASSET"
printf '%s  %s\n' "$EXPECTED" "$TMP/$ASSET" | sha256sum -c - >/dev/null || fail "探针 SHA-256 校验失败"
chmod 0755 "$TMP/$ASSET"
"$TMP/$ASSET" version >/dev/null || fail "探针二进制不可执行"
if [ "$ACTION" = install ]; then
  "$TMP/$ASSET" join --config-dir "$CONFIG_DIR" --controller "$CONTROLLER" --enrollment-token "$TOKEN" --host-name "$HOST_NAME" || fail "主控接入失败"
fi
if [ "$MANAGER" = systemd ]; then
  systemctl stop wukong-probe.service >/dev/null 2>&1 || true
else
  rc-service wukong-probe stop >/dev/null 2>&1 || true
fi
install -m 0755 "$TMP/$ASSET" "$BIN"
if [ "$MANAGER" = systemd ]; then
  cat > /etc/systemd/system/wukong-probe.service <<'UNIT'
[Unit]
Description=Wukong lightweight fleet probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wukong-probe run
Restart=always
RestartSec=5
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_RAW
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now wukong-probe.service >/dev/null || fail "无法启动探针服务"
  systemctl is-active --quiet wukong-probe.service || fail "探针服务未运行"
else
  cat > /etc/init.d/wukong-probe <<'INIT'
#!/sbin/openrc-run
name="Wukong lightweight fleet probe"
command="/usr/local/bin/wukong-probe"
command_args="run"
command_background=true
pidfile="/run/wukong-probe.pid"
depend() { need net; }
INIT
  chmod 0755 /etc/init.d/wukong-probe
  rc-update add wukong-probe default >/dev/null
  rc-service wukong-probe start >/dev/null || fail "无法启动探针服务"
  rc-service wukong-probe status >/dev/null || fail "探针服务未运行"
fi
info "轻量探针已启动；仅主动连接中央 HTTPS，不安装面板、Nginx 或 sing-box"
