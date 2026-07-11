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
ACME_IP_VERSION=""
UNATTENDED=false
SKIP_PACKAGES=false
BINARY_SOURCE="${WUKONG_BINARY:-}"
DOMAIN_SET=false
PORT_SET=false
ACME_SET=false
EMAIL_SET=false
HAS_CONFIG_ARGS=false
FORCE_INTERACTIVE=false

info() { printf '\033[1;33m[悟空]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;31m[提示]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[失败]\033[0m %s\n' "$*" >&2; exit 1; }

prompt_value() {
  prompt_label=$1
  prompt_default=$2
  if [ -n "$prompt_default" ]; then
    printf '%s [%s]: ' "$prompt_label" "$prompt_default" >/dev/tty
  else
    printf '%s: ' "$prompt_label" >/dev/tty
  fi
  IFS= read -r prompt_answer </dev/tty || prompt_answer=""
  if [ -n "$prompt_answer" ]; then printf '%s' "$prompt_answer"; else printf '%s' "$prompt_default"; fi
}

interactive_available() {
  [ "$UNATTENDED" != true ] && { [ "$FORCE_INTERACTIVE" = true ] || [ "$HAS_CONFIG_ARGS" = false ]; } && [ -r /dev/tty ] && [ -w /dev/tty ] && (: </dev/tty) 2>/dev/null
}

usage() {
  cat <<'EOF'
悟空面板安装器

用法：
  sh install.sh [参数]
  curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- [参数]

常用参数：
  --port PORT          nginx HTTPS 监听端口（默认 9443）
  --domain DOMAIN      面板域名
  --base-path PATH     随机管理路径；留空时自动生成
  --version VERSION    安装指定版本
  --acme METHOD        证书方式：http、cloudflare、selfsigned
  --acme-ip-version 4|6  HTTP-01 强制通过 IPv4 或 IPv6 验证
  --email EMAIL        Let's Encrypt 账户邮箱
  --interactive        即使提供了参数也进入交互向导
  --unattended         无人值守安装
  --help               显示本帮助

NAT/受限端口 VPS 示例：
  curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- --port 你的可用TCP端口
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --domain) DOMAIN="$2"; DOMAIN_SET=true; HAS_CONFIG_ARGS=true; shift 2 ;;
    --port) PORT="$2"; PORT_SET=true; HAS_CONFIG_ARGS=true; shift 2 ;;
    --base-path) BASE_PATH="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --acme) ACME_METHOD="$2"; ACME_SET=true; HAS_CONFIG_ARGS=true; shift 2 ;;
    --acme-ip-version) ACME_IP_VERSION="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --cert-file) CERT_FILE="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --key-file) KEY_FILE="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --email) EMAIL="$2"; EMAIL_SET=true; HAS_CONFIG_ARGS=true; shift 2 ;;
    --binary) BINARY_SOURCE="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --interactive) FORCE_INTERACTIVE=true; shift ;;
    --unattended|-y|--yes) UNATTENDED=true; shift ;;
    --skip-packages) SKIP_PACKAGES=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "请使用 root 或 sudo 执行安装器"

if interactive_available; then
  info "进入交互安装向导（直接回车采用默认值）"
  if [ "$DOMAIN_SET" != true ]; then
    DOMAIN=$(prompt_value "面板域名（留空则使用 IP 和自签名证书）" "$DOMAIN")
  fi
  if [ "$PORT_SET" != true ]; then
    PORT=$(prompt_value "面板 HTTPS 端口" "$PORT")
  fi
  if [ -n "$DOMAIN" ] && [ "$ACME_SET" != true ]; then
    printf '%s\n' "请选择 TLS 证书方式：" "  1) Let's Encrypt HTTP-01（推荐，域名需指向本机且公网 80 可达）" "  2) Let's Encrypt Cloudflare DNS-01" "  3) 自签名证书" >/dev/tty
    cert_choice=$(prompt_value "选择" "1")
    case "$cert_choice" in 1|http) ACME_METHOD=http ;; 2|cloudflare) ACME_METHOD=cloudflare ;; 3|selfsigned) ACME_METHOD=selfsigned ;; *) die "无效的证书方式选项: $cert_choice" ;; esac
  fi
  if [ "$ACME_METHOD" = "http" ] && [ -z "$ACME_IP_VERSION" ]; then
    printf '%s\n' "请选择 HTTP-01 验证网络：" "  1) 自动选择" "  2) 仅 IPv4" "  3) 仅 IPv6（适合 IPv4 NAT 端口受限的 VPS）" >/dev/tty
    ip_choice=$(prompt_value "选择" "1")
    case "$ip_choice" in 1|auto) ACME_IP_VERSION="" ;; 2|4) ACME_IP_VERSION=4 ;; 3|6) ACME_IP_VERSION=6 ;; *) die "无效的 IP 版本选项: $ip_choice" ;; esac
  fi
  if { [ "$ACME_METHOD" = "http" ] || [ "$ACME_METHOD" = "cloudflare" ]; } && [ "$EMAIL_SET" != true ]; then
    email_default="admin@$(printf '%s' "$DOMAIN" | cut -d. -f2-)"
    EMAIL=$(prompt_value "Let's Encrypt 账户邮箱" "$email_default")
  fi
  printf '\n安装配置确认\n  域名: %s\n  HTTPS 端口: %s\n  证书方式: %s\n  HTTP-01 网络: %s\n\n' "${DOMAIN:-不使用域名}" "$PORT" "$ACME_METHOD" "${ACME_IP_VERSION:-自动/不适用}" >/dev/tty
  confirm_install=$(prompt_value "确认开始安装？(Y/n)" "Y")
  case "$confirm_install" in Y|y|yes|YES|Yes) ;; *) info "已取消安装"; exit 0 ;; esac
fi

case "$PORT" in ''|*[!0-9]*) die "--port 必须是 1-65535 的数字" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port 必须是 1-65535 的数字"
case "$ACME_METHOD" in selfsigned|http|cloudflare) ;; *) die "--acme 必须是 http、cloudflare 或 selfsigned" ;; esac
case "$ACME_IP_VERSION" in ''|4|6) ;; *) die "--acme-ip-version 必须是 4 或 6" ;; esac
[ -z "$DOMAIN" ] && { [ "$ACME_METHOD" = "selfsigned" ] || die "申请 Let's Encrypt 证书必须填写 --domain"; }
if [ -n "$DOMAIN" ]; then
  case "$DOMAIN" in *[!A-Za-z0-9.-]*|.*|*.) die "域名格式无效，请只填写主机名，不要包含 https://、端口或路径" ;; esac
  printf '%s\n' "$DOMAIN" | awk -F. '
    length($0) > 253 || NF < 2 { exit 1 }
    { for (i = 1; i <= NF; i++) if (length($i) < 1 || length($i) > 63 || $i !~ /^[A-Za-z0-9]/ || $i !~ /[A-Za-z0-9]$/) exit 1 }
  ' || die "域名格式无效，请检查各级域名"
fi

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
    info "申请 Let's Encrypt 证书（HTTP-01${ACME_IP_VERSION:+ / IPv$ACME_IP_VERSION}）"
    case "$ACME_IP_VERSION" in
      4) /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --listen-v4 --httpport 80 --keylength ec-256 --server letsencrypt ;;
      6) /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --listen-v6 --httpport 80 --keylength ec-256 --server letsencrypt ;;
      *) /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --httpport 80 --keylength ec-256 --server letsencrypt ;;
    esac
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
  # OpenRC's start-stop-daemon opens these files after switching to command_user.
  # Pre-create them for the unprivileged Web process and keep reinstallations
  # idempotent without truncating existing logs.
  touch /var/log/wukong-agent.log /var/log/wukong-web.log
  chown root:wukong /var/log/wukong-agent.log
  chown wukong:wukong /var/log/wukong-web.log
  chmod 0640 /var/log/wukong-agent.log /var/log/wukong-web.log
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

WEB_READY=false
attempt=0
while [ "$attempt" -lt 30 ]; do
  if curl -fsS --max-time 2 http://127.0.0.1:8788/healthz >/dev/null 2>&1; then
    WEB_READY=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$WEB_READY" != true ]; then
  if [ "$INIT" = "systemd" ]; then
    systemctl status wukong-agent.service wukong-web.service --no-pager >&2 || true
  else
    rc-service wukong-agent status >&2 || true
    rc-service wukong-web status >&2 || true
    tail -n 30 /var/log/wukong-agent.log /var/log/wukong-web.log >&2 || true
  fi
  die "悟空 Web 服务未能在 30 秒内就绪，已停止配置 nginx"
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

IPV4_HOST=$(curl -4 -fsSL --max-time 4 https://api.ipify.org 2>/dev/null || true)
if [ -z "$IPV4_HOST" ]; then IPV4_HOST=$(hostname -I 2>/dev/null | awk '{print $1}' || true); fi
IPV6_HOST=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6 / {sub(/\/.*/, "", $2); print $2; exit}' || true)

format_url() {
  url_host=$1
  case "$url_host" in *:*) url_host="[$url_host]" ;; esac
  if [ "$PORT" = "443" ]; then
    printf 'https://%s%s' "$url_host" "$BASE_PATH"
  else
    printf 'https://%s:%s%s' "$url_host" "$PORT" "$BASE_PATH"
  fi
}

printf '\n\033[1;33m悟空面板安装完成\033[0m\n'
if [ -n "$DOMAIN" ]; then
  printf '域名访问: %s\n' "$(format_url "$DOMAIN")"
fi
if [ -n "$IPV4_HOST" ]; then
  printf 'IPv4 访问: %s\n' "$(format_url "$IPV4_HOST")"
fi
if [ -n "$IPV6_HOST" ]; then
  printf 'IPv6 访问: %s\n' "$(format_url "$IPV6_HOST")"
fi
if [ -z "$DOMAIN$IPV4_HOST$IPV6_HOST" ]; then
  printf '访问地址: %s\n' "$(format_url SERVER_IP)"
fi
printf '%s\n' "$INIT_OUTPUT" | sed -n 's/^WUKONG_INITIAL_PASSWORD=/初始密码: /p'
printf '管理账号: admin\n'
printf '请在防火墙/安全组中放行 TCP %s；节点 UDP 端口按需放行。\n' "$PORT"
[ -n "$IPV4_HOST" ] && warn "NAT/受限端口 VPS 必须把公网 TCP 端口映射到本机 TCP $PORT；若映射端口不同，请使用公网映射端口访问"
[ "$ACME_METHOD" = "selfsigned" ] && warn "当前使用自签名证书，浏览器首次访问需要手动信任"
