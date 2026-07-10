#!/bin/sh
set -eu

REPO="252201/wukong-panel"
VERSION="latest"
DOMAIN=""
PORT="9443"
BASE_PATH=""
ACME_METHOD="selfsigned"
CERT_FILE=""
KEY_FILE=""
EMAIL=""
UNATTENDED=false
SKIP_PACKAGES=false
BINARY_SOURCE="${WUKONG_BINARY:-}"

info() { printf '\033[1;33m[悟空]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;31m[提示]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[失败]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请使用 root 或 sudo 执行安装器"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --base-path) BASE_PATH="$2"; shift 2 ;;
    --acme) ACME_METHOD="$2"; shift 2 ;;
    --cert-file) CERT_FILE="$2"; shift 2 ;;
    --key-file) KEY_FILE="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --binary) BINARY_SOURCE="$2"; shift 2 ;;
    --unattended|-y|--yes) UNATTENDED=true; shift ;;
    --skip-packages) SKIP_PACKAGES=true; shift ;;
    *) die "未知参数: $1" ;;
  esac
done

case "$PORT" in ''|*[!0-9]*) die "--port 必须是 1-65535 的数字" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port 必须是 1-65535 的数字"

OS_ID=""
[ -r /etc/os-release ] && OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | head -1 | tr -d '"')
case "$OS_ID" in
  debian|ubuntu) FAMILY="apt"; INIT="systemd" ;;
  rocky|almalinux|rhel|centos) FAMILY="dnf"; INIT="systemd" ;;
  alpine) FAMILY="apk"; INIT="openrc" ;;
  *) die "不支持的系统: ${OS_ID:-unknown}。首版支持 Debian、Ubuntu、Rocky、AlmaLinux、Alpine" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in x86_64|amd64) ASSET_ARCH="amd64" ;; aarch64|arm64) ASSET_ARCH="arm64" ;; *) die "不支持的架构: $ARCH" ;; esac

if [ "$SKIP_PACKAGES" != true ]; then
  info "安装运行依赖（$OS_ID / $INIT）"
  case "$FAMILY" in
    apt) apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl openssl nginx tcpdump >/dev/null ;;
    dnf) dnf install -y -q ca-certificates curl openssl nginx tcpdump shadow-utils >/dev/null ;;
    apk) apk add -q ca-certificates curl openssl nginx tcpdump ;;
  esac
fi

install -d -m 0755 /usr/local/bin /etc/wukong-panel /etc/wukong-panel/tls
if ! grep -q '^wukong:' /etc/group 2>/dev/null; then
  if [ "$FAMILY" = "apk" ]; then addgroup -S wukong; else groupadd --system wukong; fi
fi
chown root:wukong /etc/wukong-panel
chmod 0750 /etc/wukong-panel
install -d -o root -g root -m 0700 /etc/wukong-panel/secrets
if ! id wukong >/dev/null 2>&1; then
  if [ "$FAMILY" = "apk" ]; then adduser -S -D -H -s /sbin/nologin -G wukong wukong; else useradd --system --no-create-home --shell /usr/sbin/nologin --gid wukong wukong; fi
fi
install -d -o root -g wukong -m 0770 /var/lib/wukong-panel
install -d -o root -g wukong -m 0750 /run/wukong-panel

if [ -z "$BASE_PATH" ] && [ -r /etc/wukong-panel/env ]; then
  BASE_PATH=$(sed -n 's/^WUKONG_BASE_PATH=//p' /etc/wukong-panel/env | head -1)
fi
if [ -z "$BASE_PATH" ]; then BASE_PATH="/wukong-$(openssl rand -hex 12)/"; fi
case "$BASE_PATH" in /*) ;; *) BASE_PATH="/$BASE_PATH" ;; esac
case "$BASE_PATH" in */) ;; *) BASE_PATH="$BASE_PATH/" ;; esac

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

if [ -n "$BINARY_SOURCE" ]; then
  info "安装本地二进制"
  cp "$BINARY_SOURCE" "$TMP_DIR/wukong-panel"
else
  info "下载悟空面板 ${VERSION}（linux-${ASSET_ARCH}）"
  if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
  else
    case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  fi
  curl -fL --retry 3 "$BASE_URL/wukong-panel-linux-${ASSET_ARCH}" -o "$TMP_DIR/wukong-panel"
  curl -fL --retry 3 "$BASE_URL/SHA256SUMS" -o "$TMP_DIR/SHA256SUMS"
  expected=$(awk -v file="wukong-panel-linux-${ASSET_ARCH}" '$2 == file {print $1}' "$TMP_DIR/SHA256SUMS")
  [ -n "$expected" ] || die "发布清单中没有当前架构"
  actual=$(openssl dgst -sha256 "$TMP_DIR/wukong-panel" | awk '{print $NF}')
  [ "$actual" = "$expected" ] || die "二进制 SHA-256 校验失败"
fi
chmod 0755 "$TMP_DIR/wukong-panel"
if [ -x /usr/local/bin/wukong-panel ]; then
  cp /usr/local/bin/wukong-panel "/var/lib/wukong-panel/wukong-panel.before-update"
fi
install -m 0755 "$TMP_DIR/wukong-panel" /usr/local/bin/wukong-panel
ln -sf /usr/local/bin/wukong-panel /usr/local/bin/wukongctl

TLS_CERT="/etc/wukong-panel/tls/fullchain.cer"
TLS_KEY="/etc/wukong-panel/tls/private.key"
if [ -n "$CERT_FILE" ] || [ -n "$KEY_FILE" ]; then
  [ -r "$CERT_FILE" ] && [ -r "$KEY_FILE" ] || die "--cert-file 与 --key-file 必须同时提供且可读"
  TLS_CERT="$CERT_FILE"; TLS_KEY="$KEY_FILE"
elif [ "$ACME_METHOD" = "http" ] || [ "$ACME_METHOD" = "cloudflare" ]; then
  [ -n "$DOMAIN" ] || die "ACME 申请需要 --domain"
  [ -n "$EMAIL" ] || EMAIL="admin@$(printf '%s' "$DOMAIN" | cut -d. -f2-)"
  if [ ! -x /root/.acme.sh/acme.sh ]; then curl -fsSL https://get.acme.sh | sh -s email="$EMAIL" >/dev/null; fi
  if [ "$ACME_METHOD" = "http" ]; then
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:|\])80$'; then die "公网 80 已被占用；请改用 --acme cloudflare 或导入现有证书"; fi
    /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --httpport 80 --keylength ec-256 --server letsencrypt
  else
    [ -n "${CF_Token:-}" ] || die "Cloudflare DNS-01 需要 CF_Token"
    [ -n "${CF_Zone_ID:-${CF_Account_ID:-}}" ] || die "Cloudflare DNS-01 还需要 CF_Zone_ID 或 CF_Account_ID"
    /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --dns dns_cf --keylength ec-256 --server letsencrypt
  fi
  /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc --fullchain-file "$TLS_CERT" --key-file "$TLS_KEY" --reloadcmd "nginx -t && nginx -s reload || true"
else
  if [ ! -s "$TLS_CERT" ] || [ ! -s "$TLS_KEY" ]; then
    info "生成自签名 HTTPS 证书"
    CN=${DOMAIN:-wukong-panel.local}
    openssl ecparam -genkey -name prime256v1 -out "$TLS_KEY" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$TLS_KEY" -out "$TLS_CERT" -subj "/CN=$CN" >/dev/null 2>&1
  fi
fi
chmod 0600 "$TLS_KEY"

cat > /etc/wukong-panel/env <<EOF
WUKONG_DATA_DIR=/var/lib/wukong-panel
WUKONG_SECRET_DIR=/etc/wukong-panel/secrets
WUKONG_AGENT_SOCKET=/run/wukong-panel/agent.sock
WUKONG_AGENT_TOKEN_FILE=/etc/wukong-panel/agent.token
WUKONG_SINGBOX_CONFIG_DIR=/etc/s-box
WUKONG_SINGBOX_BIN=/etc/s-box/sing-box
WUKONG_LISTEN=127.0.0.1:8788
WUKONG_BASE_PATH=$BASE_PATH
WUKONG_SECURE_COOKIE=true
EOF
chown root:wukong /etc/wukong-panel/env
chmod 0640 /etc/wukong-panel/env

INIT_OUTPUT=$(/usr/local/bin/wukong-panel init --data-dir /var/lib/wukong-panel --secret-dir /etc/wukong-panel/secrets --agent-token-file /etc/wukong-panel/agent.token --base-path "$BASE_PATH")
chown root:wukong /var/lib/wukong-panel /var/lib/wukong-panel/wukong.db /etc/wukong-panel/agent.token
chmod 0770 /var/lib/wukong-panel
chmod 0660 /var/lib/wukong-panel/wukong.db
chmod 0640 /etc/wukong-panel/agent.token
chmod 0600 /etc/wukong-panel/secrets/master.key

if [ "$INIT" = "systemd" ]; then
  cat > /etc/systemd/system/wukong-agent.service <<'EOF'
[Unit]
Description=Wukong Panel privileged node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=wukong
UMask=0007
EnvironmentFile=/etc/wukong-panel/env
ExecStart=/usr/local/bin/wukong-panel agent
Restart=on-failure
RestartSec=3s
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/wukong-web.service <<'EOF'
[Unit]
Description=Wukong Panel web service
After=network-online.target wukong-agent.service
Requires=wukong-agent.service

[Service]
Type=simple
User=wukong
Group=wukong
UMask=0007
EnvironmentFile=/etc/wukong-panel/env
ExecStart=/usr/local/bin/wukong-panel web
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/wukong-panel

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now wukong-agent.service wukong-web.service
else
  cat > /etc/init.d/wukong-agent <<'EOF'
#!/sbin/openrc-run
name="Wukong Panel Agent"
command="/usr/local/bin/wukong-panel"
command_args="agent"
command_user="root:wukong"
command_background=true
pidfile="/run/wukong-panel/agent.pid"
output_log="/var/log/wukong-agent.log"
error_log="/var/log/wukong-agent.log"
export WUKONG_DATA_DIR=/var/lib/wukong-panel WUKONG_SECRET_DIR=/etc/wukong-panel/secrets WUKONG_AGENT_SOCKET=/run/wukong-panel/agent.sock WUKONG_AGENT_TOKEN_FILE=/etc/wukong-panel/agent.token WUKONG_SINGBOX_CONFIG_DIR=/etc/s-box WUKONG_SINGBOX_BIN=/etc/s-box/sing-box
depend() { need net; }
EOF
  cat > /etc/init.d/wukong-web <<EOF
#!/sbin/openrc-run
name="Wukong Panel Web"
command="/usr/local/bin/wukong-panel"
command_args="web"
command_user="wukong:wukong"
command_background=true
pidfile="/run/wukong-panel/web.pid"
output_log="/var/log/wukong-web.log"
error_log="/var/log/wukong-web.log"
export WUKONG_DATA_DIR=/var/lib/wukong-panel WUKONG_SECRET_DIR=/etc/wukong-panel/secrets WUKONG_AGENT_SOCKET=/run/wukong-panel/agent.sock WUKONG_AGENT_TOKEN_FILE=/etc/wukong-panel/agent.token WUKONG_SINGBOX_CONFIG_DIR=/etc/s-box WUKONG_SINGBOX_BIN=/etc/s-box/sing-box WUKONG_LISTEN=127.0.0.1:8788 WUKONG_BASE_PATH=$BASE_PATH WUKONG_SECURE_COOKIE=true
depend() { need net wukong-agent; }
EOF
  chmod 0755 /etc/init.d/wukong-agent /etc/init.d/wukong-web
  rc-update add wukong-agent default >/dev/null
  rc-update add wukong-web default >/dev/null
  rc-service wukong-agent restart
  rc-service wukong-web restart
fi

SERVER_NAME=${DOMAIN:-_}
if [ "$FAMILY" = "apk" ]; then NGINX_PANEL_CONF=/etc/nginx/http.d/wukong-panel.conf; else NGINX_PANEL_CONF=/etc/nginx/conf.d/wukong-panel.conf; fi
cat > "$NGINX_PANEL_CONF" <<EOF
server {
    listen $PORT ssl;
    listen [::]:$PORT ssl;
    server_name $SERVER_NAME;
    ssl_certificate $TLS_CERT;
    ssl_certificate_key $TLS_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    location = ${BASE_PATH%/} { return 308 $BASE_PATH; }
    location ^~ $BASE_PATH {
        proxy_pass http://127.0.0.1:8788/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_buffering off;
        proxy_read_timeout 75s;
    }
}
EOF
nginx -t
if [ "$INIT" = "systemd" ]; then systemctl enable --now nginx; systemctl reload nginx; else rc-update add nginx default >/dev/null 2>&1 || true; rc-service nginx restart; fi

HOST=${DOMAIN:-$(curl -4 -fsSL --max-time 4 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')}
[ -n "$HOST" ] || HOST="SERVER_IP"
if [ "$PORT" = "443" ]; then URL="https://${HOST}${BASE_PATH}"; else URL="https://${HOST}:${PORT}${BASE_PATH}"; fi

printf '\n\033[1;33m悟空面板安装完成\033[0m\n'
printf '访问地址: %s\n' "$URL"
printf '%s\n' "$INIT_OUTPUT" | sed -n 's/^WUKONG_INITIAL_PASSWORD=/初始密码: /p'
printf '管理账号: admin\n'
printf '请在防火墙/安全组中放行 TCP %s；节点 UDP 端口按需放行。\n' "$PORT"
[ "$ACME_METHOD" = "selfsigned" ] && warn "当前使用自签名证书，浏览器首次访问需要手动信任"
