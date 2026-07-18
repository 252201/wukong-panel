#!/bin/sh
set -eu

REPO="252201/wukong-panel"
VERSION="latest"
ACTION="auto"
SINGBOX_VERSION="1.13.14"
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
MIGRATOR_SOURCE="${WUKONG_MIGRATOR_BINARY:-}"
DOMAIN_SET=false
PORT_SET=false
ACME_SET=false
EMAIL_SET=false
HAS_CONFIG_ARGS=false
FORCE_INTERACTIVE=false
PURGE=false
PROMPT_TTY="/dev/tty"
RECONFIGURE_ARGS=false
SINGBOX_TRANSACTION_ROOT="${WUKONG_SINGBOX_TRANSACTION_ROOT:-/var/lib/wukong-panel/backups/sing-box/transaction}"
SINGBOX_BACKUP_ROOT="${WUKONG_SINGBOX_BACKUP_ROOT:-/var/lib/wukong-panel/backups/sing-box}"
SINGBOX_TRANSACTION_ACTIVE=false
SINGBOX_RUNTIME_BIN=""
SINGBOX_RUNTIME_CONFIG_DIR=""

info() { printf '\033[1;33m[悟空]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;31m[提示]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[失败]\033[0m %s\n' "$*" >&2; exit 1; }

detect_prompt_tty() {
  detected="/dev/tty"
  process_id=$$
  while [ "$process_id" -gt 1 ] && [ -r "/proc/$process_id/status" ]; do
    candidate=$(readlink "/proc/$process_id/fd/0" 2>/dev/null || true)
    case "$candidate" in /dev/pts/*|/dev/tty*) [ -r "$candidate" ] && [ -w "$candidate" ] && detected="$candidate" ;; esac
    parent_id=$(awk '/^PPid:/ {print $2}' "/proc/$process_id/status" 2>/dev/null || true)
    case "$parent_id" in ''|*[!0-9]*) break ;; esac
    [ "$parent_id" -ne "$process_id" ] || break
    process_id=$parent_id
  done
  printf '%s' "$detected"
}

accept_acme_issue_status() {
  case "$1" in
    0) ;;
    2) info "检测到已有未到续期时间的有效证书，跳过重复签发并继续安装" ;;
    *) die "Let's Encrypt 证书申请失败（acme.sh 返回码 $1）" ;;
  esac
}

prompt_value() {
  prompt_label=$1
  prompt_default=$2
  if [ -n "$prompt_default" ]; then
    printf '%s [%s]: ' "$prompt_label" "$prompt_default" >"$PROMPT_TTY"
  else
    printf '%s: ' "$prompt_label" >"$PROMPT_TTY"
  fi
  IFS= read -r prompt_answer <"$PROMPT_TTY" || prompt_answer=""
  if [ -n "$prompt_answer" ]; then printf '%s' "$prompt_answer"; else printf '%s' "$prompt_default"; fi
}

interactive_available() {
  [ "$UNATTENDED" != true ] && { [ "$FORCE_INTERACTIVE" = true ] || [ "$HAS_CONFIG_ARGS" = false ]; } && [ -r "$PROMPT_TTY" ] && [ -w "$PROMPT_TTY" ]
}

panel_installed() {
  [ -x /usr/local/bin/wukong-panel ] && [ -r /etc/wukong-panel/env ]
}

resolve_auto_action() {
  installed=$1
  reconfigure=$2
  if [ "$installed" = true ] && [ "$reconfigure" != true ]; then printf 'update'; else printf 'install'; fi
}

using_systemd() {
  [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

sha256_file() {
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    die "缺少 openssl 或 sha256sum，无法校验下载包"
  fi
}

uninstall_panel() {
  purge=$1
  info "停止并卸载悟空面板"
  if [ "$purge" = true ]; then disable_certificate_renewal; fi
  if using_systemd; then
    systemctl disable --now wukong-web.service wukong-agent.service 2>/dev/null || true
    rm -f /etc/systemd/system/wukong-web.service /etc/systemd/system/wukong-agent.service
    systemctl daemon-reload
  else
    rc-service wukong-web stop 2>/dev/null || true
    rc-service wukong-agent stop 2>/dev/null || true
    rc-update del wukong-web default 2>/dev/null || true
    rc-update del wukong-agent default 2>/dev/null || true
    rm -f /etc/init.d/wukong-web /etc/init.d/wukong-agent
  fi
  rm -f /etc/nginx/conf.d/wukong-panel.conf /etc/nginx/http.d/wukong-panel.conf
  rm -f /usr/local/bin/wukong-panel /usr/local/bin/wukongctl
  if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
    if using_systemd; then systemctl reload nginx 2>/dev/null || true; else rc-service nginx reload 2>/dev/null || true; fi
  fi
  if [ "$purge" = true ]; then
    rm -rf /var/lib/wukong-panel /etc/wukong-panel /run/wukong-panel
    rm -f /var/log/wukong-agent.log /var/log/wukong-web.log
    info "面板程序、配置和数据已彻底删除"
  else
    info "已保留 /var/lib/wukong-panel 与 /etc/wukong-panel，重新安装可恢复数据"
  fi
  info "悟空面板已卸载；sing-box 节点、节点配置和节点服务未改动"
}

download_panel_binary() {
  if [ -n "$BINARY_SOURCE" ]; then
    info "读取本地二进制"
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
    actual=$(sha256_file "$TMP_DIR/wukong-panel")
    [ "$actual" = "$expected" ] || die "二进制 SHA-256 校验失败"
  fi
  chmod 0755 "$TMP_DIR/wukong-panel"
}

stop_panel_services() {
  if using_systemd; then
    systemctl stop wukong-web.service wukong-agent.service 2>/dev/null || true
  else
    rc-service wukong-web stop 2>/dev/null || true
    rc-service wukong-agent stop 2>/dev/null || true
  fi
}

start_panel_services() {
  if using_systemd; then
    systemctl restart wukong-agent.service && systemctl restart wukong-web.service
  else
    rc-service wukong-agent restart && rc-service wukong-web restart
  fi
}

reset_panel_password() {
  database=/var/lib/wukong-panel/wukong.db
  [ -r "$database" ] || die "未找到面板数据库 $database，无法重置密码"
  download_panel_binary
  timestamp=$(date +%Y%m%d-%H%M%S)
  backup_dir="/var/lib/wukong-panel/backups/password-reset-$timestamp-$$"
  install -d -m 0700 "$backup_dir"
  info "停止面板服务并备份数据库"
  stop_panel_services
  for database_file in /var/lib/wukong-panel/wukong.db*; do
    [ -e "$database_file" ] || continue
    if ! cp -a "$database_file" "$backup_dir/"; then
      start_panel_services || true
      die "数据库备份失败，密码未重置"
    fi
  done
  if ! reset_output=$("$TMP_DIR/wukong-panel" reset-password --data-dir /var/lib/wukong-panel 2>&1); then
    start_panel_services || true
    die "密码重置失败：$reset_output"
  fi
  printf '%s\n' "$reset_output"
  if ! start_panel_services; then
    die "密码已重置，但面板服务恢复失败；数据库备份位于 $backup_dir"
  fi
  if ! health=$(wait_for_web); then
    die "密码已重置且服务已启动，但健康检查未通过；数据库备份位于 $backup_dir"
  fi
  info "面板密码重置完成：$health"
  info "重置前数据库备份：$backup_dir"
}

wait_for_web() {
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if curl -fsS --max-time 2 http://127.0.0.1:8788/healthz 2>/dev/null; then return 0; fi
    attempt=$((attempt + 1))
    sleep 1
  done
  return 1
}

backfill_panel_domain() {
  env_file=/etc/wukong-panel/env
  [ -r "$env_file" ] || return 0
  grep -q '^WUKONG_PANEL_DOMAIN=' "$env_file" && return 0
  panel_domain=""
  for nginx_config in /etc/nginx/conf.d/wukong-panel.conf /etc/nginx/http.d/wukong-panel.conf; do
    [ -r "$nginx_config" ] || continue
    panel_domain=$(awk '$1 == "server_name" { value=$2; sub(/;$/, "", value); if (value != "_") { print value; exit } }' "$nginx_config")
    [ -z "$panel_domain" ] || break
  done
  printf '\nWUKONG_PANEL_DOMAIN=%s\n' "$panel_domain" >> "$env_file"
  info "已记录面板域名：${panel_domain:-未配置域名}"
}

backfill_panel_tls() {
  env_file=${1:-/etc/wukong-panel/env}
  if [ "$#" -gt 0 ]; then shift; fi
  [ -r "$env_file" ] || return 0
  if grep -q '^WUKONG_TLS_CERT=[^[:space:]]' "$env_file" && grep -q '^WUKONG_TLS_KEY=[^[:space:]]' "$env_file"; then
    return 0
  fi
  panel_domain=$(sed -n 's/^WUKONG_PANEL_DOMAIN=//p' "$env_file" | tail -1)
  if [ "$#" -eq 0 ]; then
    set -- /etc/nginx/conf.d/wukong-panel.conf /etc/nginx/http.d/wukong-panel.conf
  fi
  for nginx_config in "$@"; do
    [ -r "$nginx_config" ] || continue
    tls_cert=$(awk '$1 == "ssl_certificate" { value=$2; sub(/;$/, "", value); print value; exit }' "$nginx_config")
    tls_key=$(awk '$1 == "ssl_certificate_key" { value=$2; sub(/;$/, "", value); print value; exit }' "$nginx_config")
    [ -r "$tls_cert" ] && [ -r "$tls_key" ] || continue
    openssl x509 -in "$tls_cert" -noout -checkend 0 >/dev/null 2>&1 || continue
    if [ -n "$panel_domain" ]; then
      openssl x509 -in "$tls_cert" -noout -checkhost "$panel_domain" >/dev/null 2>&1 || continue
    fi
    cert_public=$(openssl x509 -in "$tls_cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}')
    key_public=$(openssl pkey -in "$tls_key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}')
    [ -n "$cert_public" ] && [ "$cert_public" = "$key_public" ] || continue
    printf '\nWUKONG_TLS_CERT=%s\nWUKONG_TLS_KEY=%s\n' "$tls_cert" "$tls_key" >> "$env_file"
    info "已记录可信 TLS 证书：$tls_cert"
    return 0
  done
  warn "未能从面板 Nginx 配置识别可复用的 TLS 证书；新建证书协议节点将继续使用自签名证书"
}

install_certificate_renewal_helpers() {
  install -d -m 0755 /usr/local/sbin
  reload_hook=/usr/local/sbin/wukong-cert-reload
  cat > "$reload_hook" <<'EOF_WUKONG_CERT_RELOAD'
#!/bin/sh
set -eu

env_file=${WUKONG_ENV_FILE:-/etc/wukong-panel/env}
env_value() {
  [ -r "$env_file" ] || return 0
  sed -n "s/^$1=//p" "$env_file" | tail -1
}

tls_cert=$(env_value WUKONG_TLS_CERT)
config_dir=$(env_value WUKONG_SINGBOX_CONFIG_DIR)
singbox_bin=$(env_value WUKONG_SINGBOX_BIN)
config_dir=${config_dir:-/etc/s-box}
singbox_bin=${singbox_bin:-/etc/s-box/sing-box}
[ -r "$tls_cert" ] || { printf 'Wukong TLS certificate is unavailable: %s\n' "$tls_cert" >&2; exit 1; }

restarted=" "
failed=0
restart_systemd_config() {
  config=$1
  for unit_file in /etc/systemd/system/sing-box*.service /usr/lib/systemd/system/sing-box*.service /lib/systemd/system/sing-box*.service; do
    [ -f "$unit_file" ] || continue
    grep -F "$config" "$unit_file" >/dev/null 2>&1 || continue
    unit=$(basename "$unit_file")
    case "$restarted" in *" $unit "*) continue ;; esac
    if systemctl is-active --quiet "$unit"; then systemctl restart "$unit" || failed=1; fi
    restarted="$restarted$unit "
  done
}
restart_openrc_config() {
  config=$1
  for init_script in /etc/init.d/sing-box*; do
    [ -f "$init_script" ] || continue
    grep -F "$config" "$init_script" >/dev/null 2>&1 || continue
    service=$(basename "$init_script")
    case "$restarted" in *" $service "*) continue ;; esac
    if rc-service "$service" status >/dev/null 2>&1; then rc-service "$service" restart || failed=1; fi
    restarted="$restarted$service "
  done
}

for config in "$config_dir"/*.json; do
  [ -f "$config" ] || continue
  grep -F "$tls_cert" "$config" >/dev/null 2>&1 || continue
  if ! "$singbox_bin" check -c "$config"; then
    printf 'Refusing to restart invalid sing-box config: %s\n' "$config" >&2
    failed=1
    continue
  fi
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    restart_systemd_config "$config"
  elif command -v rc-service >/dev/null 2>&1; then
    restart_openrc_config "$config"
  fi
done

if command -v nginx >/dev/null 2>&1; then
  nginx -t
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx.service; then
    systemctl reload nginx.service || failed=1
  elif command -v rc-service >/dev/null 2>&1 && rc-service nginx status >/dev/null 2>&1; then
    rc-service nginx reload || failed=1
  fi
fi
exit "$failed"
EOF_WUKONG_CERT_RELOAD
  chmod 0755 "$reload_hook"

  renew_hook=/usr/local/sbin/wukong-cert-renew
  cat > "$renew_hook" <<'EOF_WUKONG_CERT_RENEW'
#!/bin/sh
set -eu

acme_home=${WUKONG_ACME_HOME:-/root/.acme.sh}
acme="$acme_home/acme.sh"
[ -x "$acme" ] || { printf 'acme.sh is unavailable: %s\n' "$acme" >&2; exit 1; }

now=$(date +%s)
standalone_due=false
for conf in "$acme_home"/*/*.conf; do
  [ -r "$conf" ] || continue
  webroot=$(sed -n "s/^Le_Webroot='\(.*\)'/\1/p" "$conf" | tail -1)
  next_renew=$(sed -n "s/^Le_NextRenewTime='\([0-9][0-9]*\)'/\1/p" "$conf" | tail -1)
  case "$next_renew" in ''|*[!0-9]*) next_renew=0 ;; esac
  if [ "$webroot" = "no" ] && { [ "$next_renew" -eq 0 ] || [ "$next_renew" -le "$now" ]; }; then
    standalone_due=true
    break
  fi
done

nginx_manager=""
if [ "$standalone_due" = true ]; then
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx.service; then
    systemctl stop nginx.service
    nginx_manager=systemd
  elif command -v rc-service >/dev/null 2>&1 && rc-service nginx status >/dev/null 2>&1; then
    rc-service nginx stop
    nginx_manager=openrc
  fi
fi

restore_nginx() {
  status=$?
  trap - EXIT HUP INT TERM
  case "$nginx_manager" in
    systemd) systemctl start nginx.service || status=1 ;;
    openrc) rc-service nginx start || status=1 ;;
  esac
  exit "$status"
}
trap restore_nginx EXIT HUP INT TERM
"$acme" --cron --home "$acme_home"
EOF_WUKONG_CERT_RENEW
  chmod 0755 "$renew_hook"
}

configure_certificate_renewal() {
  domain=$1
  cert_file=$2
  key_file=$3
  [ -n "$domain" ] && [ -r "$cert_file" ] && [ -r "$key_file" ] || return 1
  [ -x /root/.acme.sh/acme.sh ] || return 1
  install_certificate_renewal_helpers
  /root/.acme.sh/acme.sh --install-cert -d "$domain" --ecc --fullchain-file "$cert_file" --key-file "$key_file" --reloadcmd "/usr/local/sbin/wukong-cert-reload"
  /root/.acme.sh/acme.sh --uninstall-cronjob >/dev/null 2>&1 || true
  if using_systemd; then
    cat > /etc/systemd/system/wukong-cert-renew.service <<'EOF'
[Unit]
Description=Renew Wukong Panel ACME certificates
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wukong-cert-renew
EOF
    cat > /etc/systemd/system/wukong-cert-renew.timer <<'EOF'
[Unit]
Description=Daily Wukong Panel certificate renewal check

[Timer]
OnCalendar=*-*-* 03:20:00
RandomizedDelaySec=40m
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now wukong-cert-renew.timer
  else
    install -d -m 0755 /etc/periodic/daily
    cat > /etc/periodic/daily/wukong-cert-renew <<'EOF'
#!/bin/sh
exec /usr/local/sbin/wukong-cert-renew
EOF
    chmod 0755 /etc/periodic/daily/wukong-cert-renew
    rc-update add crond default >/dev/null 2>&1 || true
    rc-service crond status >/dev/null 2>&1 || rc-service crond start
  fi
  info "已启用 Let's Encrypt 每日自动续期与节点证书热更新"
}

backfill_certificate_renewal() {
  env_file=/etc/wukong-panel/env
  [ -r "$env_file" ] || return 0
  domain=$(sed -n 's/^WUKONG_PANEL_DOMAIN=//p' "$env_file" | tail -1)
  cert_file=$(sed -n 's/^WUKONG_TLS_CERT=//p' "$env_file" | tail -1)
  key_file=$(sed -n 's/^WUKONG_TLS_KEY=//p' "$env_file" | tail -1)
  [ -n "$domain" ] && [ -r "$cert_file" ] && [ -r "$key_file" ] || return 0
  acme_conf="/root/.acme.sh/${domain}_ecc/${domain}.conf"
  [ -r "$acme_conf" ] || return 0
  installed_cert=$(sed -n "s/^Le_RealFullChainPath='\(.*\)'/\1/p" "$acme_conf" | tail -1)
  [ "$installed_cert" = "$cert_file" ] || { warn "ACME 安装路径与面板证书路径不一致，跳过自动续期接管"; return 0; }
  configure_certificate_renewal "$domain" "$cert_file" "$key_file"
}

disable_certificate_renewal() {
  if using_systemd; then
    systemctl disable --now wukong-cert-renew.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/wukong-cert-renew.timer /etc/systemd/system/wukong-cert-renew.service
    systemctl daemon-reload >/dev/null 2>&1 || true
  else
    rm -f /etc/periodic/daily/wukong-cert-renew
  fi
  rm -f /usr/local/sbin/wukong-cert-renew /usr/local/sbin/wukong-cert-reload
}

update_panel() {
  backfill_panel_domain
  backfill_panel_tls
  backfill_certificate_renewal
  download_panel_binary
  timestamp=$(date +%Y%m%d-%H%M%S)
  backup_dir="/var/lib/wukong-panel/backups/update-$timestamp"
  install -d -m 0700 "$backup_dir"
  cp -a /usr/local/bin/wukong-panel "$backup_dir/wukong-panel"
  [ ! -r /etc/wukong-panel/env ] || cp -a /etc/wukong-panel/env "$backup_dir/env"
  stop_panel_services
  for database_file in /var/lib/wukong-panel/wukong.db*; do
    [ -e "$database_file" ] || continue
    if ! cp -a "$database_file" "$backup_dir/"; then
      start_panel_services || true
      die "数据库备份失败，已取消更新"
    fi
  done
  if ! install -m 0755 "$TMP_DIR/wukong-panel" /usr/local/bin/wukong-panel || ! ln -sf /usr/local/bin/wukong-panel /usr/local/bin/wukongctl; then
    install -m 0755 "$backup_dir/wukong-panel" /usr/local/bin/wukong-panel
    start_panel_services || true
    die "替换二进制失败，已恢复更新前版本"
  fi
  if start_panel_services && health=$(wait_for_web); then
    info "悟空面板更新完成：$health"
    info "更新前备份：$backup_dir"
    return 0
  fi
  warn "新版本启动失败，正在自动回滚"
  stop_panel_services
  install -m 0755 "$backup_dir/wukong-panel" /usr/local/bin/wukong-panel
  rm -f /var/lib/wukong-panel/wukong.db /var/lib/wukong-panel/wukong.db-shm /var/lib/wukong-panel/wukong.db-wal
  for database_file in "$backup_dir"/wukong.db*; do
    [ -e "$database_file" ] || continue
    cp -a "$database_file" /var/lib/wukong-panel/
  done
  start_panel_services || true
  die "更新失败，已恢复更新前版本；备份位于 $backup_dir"
}

singbox_binary_path() {
  path=""
  if [ -r /etc/wukong-panel/env ]; then path=$(sed -n 's/^WUKONG_SINGBOX_BIN=//p' /etc/wukong-panel/env | head -1); fi
  printf '%s' "${path:-/etc/s-box/sing-box}"
}

singbox_config_dir() {
  path=""
  if [ -r /etc/wukong-panel/env ]; then path=$(sed -n 's/^WUKONG_SINGBOX_CONFIG_DIR=//p' /etc/wukong-panel/env | head -1); fi
  printf '%s' "${path:-/etc/s-box}"
}

singbox_version_of() {
  "$1" version 2>/dev/null | sed -n 's/^sing-box version //p' | head -1
}

singbox_expected_sha256() {
  case "$1-$2" in
    1.13.14-amd64) printf 'f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697' ;;
    1.13.14-arm64) printf '4742df6a4314e8ecc41736849fca6d73b8f9e91b6e8b06ee794ff17ba180579e' ;;
    1.11.15-amd64) printf '950af37eb2d7e55dddae34a18411cd617303fd99d2dc75bc76b6dd9fcd97d9c5' ;;
    1.11.15-arm64) printf '20a6a9cd259a95411599f811a5066513a98db63705a51121252ad27daf96c029' ;;
    *) return 1 ;;
  esac
}

download_singbox_binary() {
  download_target_version=${SINGBOX_VERSION#v}
  download_expected=$(singbox_expected_sha256 "$download_target_version" "$ASSET_ARCH") || die "悟空面板尚未验证 sing-box $download_target_version / $ASSET_ARCH，请先更新面板的版本清单"
  command -v tar >/dev/null 2>&1 || die "缺少 tar，无法解压 sing-box"
  download_archive="sing-box-${download_target_version}-linux-${ASSET_ARCH}.tar.gz"
  download_url="https://github.com/SagerNet/sing-box/releases/download/v${download_target_version}/${download_archive}"
  info "下载悟空验证版本 sing-box $download_target_version（linux-$ASSET_ARCH）"
  curl -fL --retry 3 "$download_url" -o "$TMP_DIR/$download_archive"
  download_actual=$(sha256_file "$TMP_DIR/$download_archive")
  [ "$download_actual" = "$download_expected" ] || die "sing-box 官方资产 SHA-256 校验失败"
  tar -xzf "$TMP_DIR/$download_archive" -C "$TMP_DIR"
  SINGBOX_CANDIDATE="$TMP_DIR/sing-box-${download_target_version}-linux-${ASSET_ARCH}/sing-box"
  [ -x "$SINGBOX_CANDIDATE" ] || die "sing-box 发布包内未找到可执行文件"
  download_candidate_version=$(singbox_version_of "$SINGBOX_CANDIDATE")
  [ "$download_candidate_version" = "$download_target_version" ] || die "sing-box 包版本不匹配：期望 $download_target_version，实际 ${download_candidate_version:-unknown}"
}

ensure_singbox_for_install() {
  ensure_binary=$(singbox_binary_path)
  ensure_config_dir=$(singbox_config_dir)
  SINGBOX_RUNTIME_BIN=$ensure_binary
  SINGBOX_RUNTIME_CONFIG_DIR=$ensure_config_dir
  [ -d "$ensure_config_dir" ] || install -d -m 0755 "$ensure_config_dir"
  if [ -x "$ensure_binary" ]; then
    ensure_version=$(singbox_version_of "$ensure_binary")
    [ -n "$ensure_version" ] || die "现有 sing-box 无法读取版本：$ensure_binary"
    info "检测到现有 sing-box ${ensure_version}，保持原版本不变"
    return 0
  fi
  [ ! -e "$ensure_binary" ] || die "sing-box 路径已存在但不可执行：$ensure_binary"
  for ensure_config_file in "$ensure_config_dir"/*.json; do
    [ ! -f "$ensure_config_file" ] || die "检测到现有 sing-box 配置但缺少配套二进制，拒绝猜测版本；请先恢复原二进制或移走旧配置"
  done
  download_singbox_binary
  ensure_stage="$ensure_binary.tmp.$$"
  install -m 0755 "$SINGBOX_CANDIDATE" "$ensure_stage"
  mv "$ensure_stage" "$ensure_binary"
  ensure_installed_version=$(singbox_version_of "$ensure_binary")
  if [ "$ensure_installed_version" != "${SINGBOX_VERSION#v}" ]; then
    rm -f "$ensure_binary"
    die "sing-box 安装后版本校验失败"
  fi
  info "已安装悟空验证版 sing-box ${ensure_installed_version}"
}

check_singbox_configs() {
  check_binary=$1
  check_config_dir=${2:-$(singbox_config_dir)}
  check_found=false
  for check_config_file in "$check_config_dir"/*.json; do
    [ -f "$check_config_file" ] || continue
    check_found=true
    if ! "$check_binary" check -c "$check_config_file"; then
      warn "配置不兼容：$check_config_file"
      return 1
    fi
  done
  [ "$check_found" = true ] || warn "未在 $check_config_dir 找到 sing-box JSON 配置"
}

prepare_singbox_migrator() {
  if [ -n "$MIGRATOR_SOURCE" ]; then
    [ -x "$MIGRATOR_SOURCE" ] || die "迁移器不可执行：$MIGRATOR_SOURCE"
    SINGBOX_MIGRATOR=$MIGRATOR_SOURCE
    return
  fi
  download_panel_binary
  SINGBOX_MIGRATOR="$TMP_DIR/wukong-panel"
}

prepare_singbox_configs() {
  prepare_source_dir=$(singbox_config_dir)
  SINGBOX_MIGRATED_DIR="$TMP_DIR/singbox-migrated"
  prepare_singbox_migrator
  info "生成 sing-box ${SINGBOX_VERSION#v} 配置迁移预览"
  "$SINGBOX_MIGRATOR" singbox plan --target "${SINGBOX_VERSION#v}" --config-dir "$prepare_source_dir"
  if [ "$INTERACTIVE_SESSION" = true ]; then
    prepare_confirm=$(prompt_value "确认按以上预览迁移配置并更新 sing-box？旧版本包会完整保留 (y/N)" "N")
    case "$prepare_confirm" in Y|y|yes|YES|Yes) ;; *) info "已取消 sing-box 更新"; exit 0 ;; esac
  fi
  "$SINGBOX_MIGRATOR" singbox migrate --target "${SINGBOX_VERSION#v}" --config-dir "$prepare_source_dir" --output-dir "$SINGBOX_MIGRATED_DIR"
  "$SINGBOX_MIGRATOR" singbox check-interfaces --target "${SINGBOX_VERSION#v}" --config-dir "$SINGBOX_MIGRATED_DIR" >/dev/null
}

install_singbox_configs() {
  install_source_dir=$1
  install_config_dir=$(singbox_config_dir)
  for install_config_file in "$install_source_dir"/*.json; do
    [ -f "$install_config_file" ] || continue
    install_config_target="$install_config_dir/$(basename "$install_config_file")"
    install -m 0600 "$install_config_file" "$install_config_target.tmp"
    mv "$install_config_target.tmp" "$install_config_target"
  done
}

restore_singbox_configs() {
  restore_source_dir=$1
  restore_config_dir=$(singbox_config_dir)
  for restore_current in "$restore_config_dir"/*.json; do [ ! -f "$restore_current" ] || rm -f "$restore_current"; done
  install_singbox_configs "$restore_source_dir"
}

probe_singbox_nodes() {
  probe_binary=$1
  probe_config_dir=${2:-$(singbox_config_dir)}
  info "按 inbound 类型执行协议级真实流量探测"
  "$SINGBOX_MIGRATOR" singbox probe --binary "$probe_binary" --config-dir "$probe_config_dir"
}

capture_active_singbox_services() {
  capture_output=$1
  capture_binary=$2
  : >"$capture_output"
  if using_systemd; then
    for capture_unit_file in /etc/systemd/system/sing-box*.service /usr/lib/systemd/system/sing-box*.service /lib/systemd/system/sing-box*.service; do
      [ -f "$capture_unit_file" ] || continue
      grep -F "$capture_binary" "$capture_unit_file" >/dev/null 2>&1 || continue
      capture_unit=$(basename "$capture_unit_file")
      systemctl is-active --quiet "$capture_unit" || continue
      printf 'systemd:%s\n' "$capture_unit" >>"$capture_output"
    done
  else
    for capture_init_file in /etc/init.d/sing-box*; do
      [ -f "$capture_init_file" ] || continue
      grep -F "$capture_binary" "$capture_init_file" >/dev/null 2>&1 || continue
      capture_service=$(basename "$capture_init_file")
      rc-service "$capture_service" status >/dev/null 2>&1 || continue
      printf 'openrc:%s\n' "$capture_service" >>"$capture_output"
    done
  fi
  sort -u "$capture_output" >"$capture_output.sorted"
  mv "$capture_output.sorted" "$capture_output"
}

capture_managed_singbox_services() {
  capture_output=$1
  capture_binary=$2
  : >"$capture_output"
  if using_systemd; then
    for capture_unit_file in /etc/systemd/system/sing-box*.service /usr/lib/systemd/system/sing-box*.service /lib/systemd/system/sing-box*.service; do
      [ -f "$capture_unit_file" ] || continue
      grep -F "$capture_binary" "$capture_unit_file" >/dev/null 2>&1 || continue
      capture_unit=$(basename "$capture_unit_file")
      capture_enabled=disabled
      systemctl is-enabled --quiet "$capture_unit" 2>/dev/null && capture_enabled=enabled
      printf 'systemd:%s:%s\n' "$capture_unit" "$capture_enabled" >>"$capture_output"
    done
  else
    for capture_init_file in /etc/init.d/sing-box*; do
      [ -f "$capture_init_file" ] || continue
      grep -F "$capture_binary" "$capture_init_file" >/dev/null 2>&1 || continue
      capture_service=$(basename "$capture_init_file")
      capture_enabled=disabled
      rc-update show default 2>/dev/null | awk '{print $1}' | grep -Fx "$capture_service" >/dev/null 2>&1 && capture_enabled=enabled
      printf 'openrc:%s:%s\n' "$capture_service" "$capture_enabled" >>"$capture_output"
    done
  fi
  sort -u "$capture_output" >"$capture_output.sorted"
  mv "$capture_output.sorted" "$capture_output"
}

stop_singbox_services() {
  stop_services_file=$1
  stop_failed=false
  while IFS=: read -r stop_manager stop_service; do
    [ -n "$stop_service" ] || continue
    if [ "$stop_manager" = systemd ]; then systemctl stop "$stop_service" || stop_failed=true; else rc-service "$stop_service" stop || stop_failed=true; fi
  done <"$stop_services_file"
  [ "$stop_failed" = false ]
}

start_singbox_services() {
  start_services_file=$1
  start_failed=false
  while IFS=: read -r start_manager start_service; do
    [ -n "$start_service" ] || continue
    if [ "$start_manager" = systemd ]; then systemctl restart "$start_service" || start_failed=true; else rc-service "$start_service" restart || start_failed=true; fi
  done <"$start_services_file"
  sleep 2
  while IFS=: read -r start_manager start_service; do
    [ -n "$start_service" ] || continue
    if [ "$start_manager" = systemd ]; then systemctl is-active --quiet "$start_service" || return 1; else rc-service "$start_service" status >/dev/null 2>&1 || return 1; fi
  done <"$start_services_file"
  [ "$start_failed" = false ]
}

backup_singbox() {
  label=$1
  binary=$2
  services_file=$3
  managed_services_file=${4:-$services_file}
  version=$(singbox_version_of "$binary")
  backup_root=$SINGBOX_BACKUP_ROOT
  backup_dir="$backup_root/$(date +%Y%m%d-%H%M%S)-$$-${label}-${version:-unknown}"
  install -d -m 0700 "$backup_dir/configs" "$backup_dir/services"
  cp -a "$binary" "$backup_dir/sing-box"
  cp -a "$services_file" "$backup_dir/active-services"
  cp -a "$managed_services_file" "$backup_dir/managed-services"
  config_dir=$(singbox_config_dir)
  for config_file in "$config_dir"/*.json; do [ ! -f "$config_file" ] || cp -a "$config_file" "$backup_dir/configs/"; done
  while IFS=: read -r backup_manager backup_service backup_enabled; do
    [ -n "$backup_service" ] || continue
    if [ "$backup_manager" = systemd ]; then
      for backup_unit in "/etc/systemd/system/$backup_service" "/usr/lib/systemd/system/$backup_service" "/lib/systemd/system/$backup_service"; do
        [ -f "$backup_unit" ] || continue
        cp -a "$backup_unit" "$backup_dir/services/"
        break
      done
    else
      [ ! -f "/etc/init.d/$backup_service" ] || cp -a "/etc/init.d/$backup_service" "$backup_dir/services/"
    fi
  done <"$managed_services_file"
  printf '%s\n' "$version" >"$backup_dir/VERSION"
  { printf '%s  sing-box\n' "$(sha256_file "$backup_dir/sing-box")"; printf '%s  active-services\n' "$(sha256_file "$backup_dir/active-services")"; printf '%s  managed-services\n' "$(sha256_file "$backup_dir/managed-services")"; for checksum_file in "$backup_dir/configs"/*.json "$backup_dir/services"/*; do [ ! -f "$checksum_file" ] || printf '%s  %s/%s\n' "$(sha256_file "$checksum_file")" "$(basename "$(dirname "$checksum_file")")" "$(basename "$checksum_file")"; done; } >"$backup_dir/SHA256SUMS"
  printf '%s' "$backup_dir"
}

verify_singbox_backup() {
  verify_backup_dir=$1
  [ -s "$verify_backup_dir/SHA256SUMS" ] || return 1
  while read -r verify_expected verify_relative; do
    [ -n "$verify_expected" ] && [ -n "$verify_relative" ] || return 1
    verify_file="$verify_backup_dir/$verify_relative"
    [ -f "$verify_file" ] || return 1
    verify_actual=$(sha256_file "$verify_file")
    [ "$verify_actual" = "$verify_expected" ] || return 1
  done <"$verify_backup_dir/SHA256SUMS"
}

remove_singbox_service_definitions() {
  remove_services_file=$1
  remove_failed=false
  while IFS=: read -r remove_manager remove_service remove_enabled; do
    [ -n "$remove_service" ] || continue
    if [ "$remove_manager" = systemd ]; then
      systemctl disable "$remove_service" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/$remove_service" "/usr/lib/systemd/system/$remove_service" "/lib/systemd/system/$remove_service" || remove_failed=true
    else
      rc-update del "$remove_service" default >/dev/null 2>&1 || true
      rm -f "/etc/init.d/$remove_service" || remove_failed=true
    fi
  done <"$remove_services_file"
  if using_systemd; then systemctl daemon-reload || remove_failed=true; fi
  [ "$remove_failed" = false ]
}

restore_singbox_service_definitions() {
  restore_backup_dir=$1
  restore_managed_file="$restore_backup_dir/managed-services"
  [ -f "$restore_managed_file" ] || return 1
  while IFS=: read -r restore_manager restore_service restore_enabled; do
    [ -n "$restore_service" ] || continue
    restore_source="$restore_backup_dir/services/$restore_service"
    [ -f "$restore_source" ] || return 1
    if [ "$restore_manager" = systemd ]; then
      install -m 0644 "$restore_source" "/etc/systemd/system/$restore_service" || return 1
    else
      install -m 0755 "$restore_source" "/etc/init.d/$restore_service" || return 1
    fi
  done <"$restore_managed_file"
  if using_systemd; then systemctl daemon-reload || return 1; fi
  while IFS=: read -r restore_manager restore_service restore_enabled; do
    [ -n "$restore_service" ] || continue
    [ "$restore_enabled" = enabled ] || continue
    if [ "$restore_manager" = systemd ]; then systemctl enable "$restore_service" >/dev/null 2>&1 || return 1; else rc-update add "$restore_service" default >/dev/null 2>&1 || return 1; fi
  done <"$restore_managed_file"
}

restore_singbox_after_uninstall_failure() {
  restore_backup_dir=$1
  restore_binary=$2
  verify_singbox_backup "$restore_backup_dir" || return 1
  [ -d "$(dirname "$restore_binary")" ] || install -d -m 0755 "$(dirname "$restore_binary")" || return 1
  install -m 0755 "$restore_backup_dir/sing-box" "$restore_binary" || return 1
  restore_singbox_configs "$restore_backup_dir/configs" || return 1
  restore_singbox_service_definitions "$restore_backup_dir" || return 1
  check_singbox_configs "$restore_binary" || return 1
  start_singbox_services "$restore_backup_dir/active-services" || return 1
}

remove_singbox_managed_files() {
  remove_binary=$1
  remove_config_dir=$2
  for remove_config_file in "$remove_config_dir"/*.json; do [ ! -f "$remove_config_file" ] || rm -f "$remove_config_file" || return 1; done
  rm -f "$remove_binary"
}

singbox_binary_is_running() {
  running_binary=$1
  for running_cmdline in /proc/[0-9]*/cmdline; do
    [ -r "$running_cmdline" ] || continue
    tr '\000' '\n' <"$running_cmdline" 2>/dev/null | grep -Fx "$running_binary" >/dev/null 2>&1 && return 0
  done
  return 1
}

uninstall_singbox() {
  uninstall_binary=$(singbox_binary_path)
  uninstall_config_dir=$(singbox_config_dir)
  [ -x "$uninstall_binary" ] || die "未找到 sing-box 二进制：$uninstall_binary"
  [ ! -e "$SINGBOX_TRANSACTION_ROOT" ] || die "存在未完成的 sing-box 更新事务，请先执行更新命令完成自动恢复"
  uninstall_active_services="$TMP_DIR/singbox-active-services"
  uninstall_managed_services="$TMP_DIR/singbox-managed-services"
  capture_active_singbox_services "$uninstall_active_services" "$uninstall_binary"
  capture_managed_singbox_services "$uninstall_managed_services" "$uninstall_binary"
  uninstall_backup_dir=$(backup_singbox uninstall "$uninstall_binary" "$uninstall_active_services" "$uninstall_managed_services")
  verify_singbox_backup "$uninstall_backup_dir" || die "sing-box 卸载备份校验失败，未修改任何文件"
  if ! stop_singbox_services "$uninstall_active_services"; then
    start_singbox_services "$uninstall_active_services" || true
    die "无法停止全部 sing-box 服务，已取消卸载"
  fi
  if singbox_binary_is_running "$uninstall_binary"; then
    start_singbox_services "$uninstall_active_services" || true
    die "仍有未受管的 sing-box 进程在运行，已取消卸载；请先停止该进程"
  fi
  if remove_singbox_service_definitions "$uninstall_managed_services" && remove_singbox_managed_files "$uninstall_binary" "$uninstall_config_dir"; then
    info "sing-box 已卸载；悟空面板和数据库保持不变"
    info "二进制、JSON 配置和服务定义备份：$uninstall_backup_dir"
    return 0
  fi
  warn "sing-box 卸载未完整完成，正在恢复卸载前状态"
  restore_singbox_after_uninstall_failure "$uninstall_backup_dir" "$uninstall_binary" || die "自动恢复失败，请立即使用备份人工恢复：$uninstall_backup_dir"
  die "sing-box 卸载失败，已恢复原二进制、配置和活动服务"
}

persist_singbox_transaction() {
  persist_backup_dir=$1
  persist_binary=$2
  persist_parent=$(dirname "$SINGBOX_TRANSACTION_ROOT")
  persist_stage="$persist_parent/.transaction-$$"
  rm -rf "$persist_stage"
  install -d -m 0700 "$persist_parent" "$persist_stage"
  printf '%s\n' "$persist_backup_dir" >"$persist_stage/backup-path"
  printf '%s\n' "$persist_binary" >"$persist_stage/binary-path"
  rm -rf "$SINGBOX_TRANSACTION_ROOT"
  mv "$persist_stage" "$SINGBOX_TRANSACTION_ROOT"
  SINGBOX_TRANSACTION_ACTIVE=true
}

clear_singbox_transaction() {
  rm -rf "$SINGBOX_TRANSACTION_ROOT"
  SINGBOX_TRANSACTION_ACTIVE=false
}

rollback_singbox_transaction() {
  [ -r "$SINGBOX_TRANSACTION_ROOT/backup-path" ] || return 0
  transaction_backup=$(sed -n '1p' "$SINGBOX_TRANSACTION_ROOT/backup-path")
  transaction_binary=$(sed -n '1p' "$SINGBOX_TRANSACTION_ROOT/binary-path")
  [ -n "$transaction_backup" ] && [ -n "$transaction_binary" ] || return 1
  verify_singbox_backup "$transaction_backup" || { warn "未完成事务的备份校验失败，拒绝自动恢复"; return 1; }
  transaction_services="$transaction_backup/active-services"
  [ -s "$transaction_services" ] || { warn "未完成事务缺少原活动服务清单，拒绝自动恢复"; return 1; }
  warn "检测到未完成的 sing-box 事务，正在恢复升级前状态"
  stop_singbox_services "$transaction_services" || true
  install -m 0755 "$transaction_backup/sing-box" "$transaction_binary" || return 1
  restore_singbox_configs "$transaction_backup/configs" || return 1
  check_singbox_configs "$transaction_binary" || return 1
  start_singbox_services "$transaction_services" || return 1
  clear_singbox_transaction
  info "已恢复未完成事务：$(singbox_version_of "$transaction_binary")，原服务已重新启动"
}

recover_pending_singbox_transaction() {
  [ -e "$SINGBOX_TRANSACTION_ROOT" ] || return 0
  SINGBOX_TRANSACTION_ACTIVE=true
  rollback_singbox_transaction || die "存在未完成的 sing-box 事务且自动恢复失败；已停止本次更新，请人工检查 $SINGBOX_TRANSACTION_ROOT"
}

update_singbox() {
  singbox_binary=$(singbox_binary_path)
  [ -x "$singbox_binary" ] || die "未找到 sing-box 二进制：$singbox_binary"
  if [ -e "$SINGBOX_TRANSACTION_ROOT" ]; then
    recover_pending_singbox_transaction
    info "未完成事务已恢复；为便于确认节点连通性，本次不再继续升级，请检查后重新执行更新"
    return 0
  fi
  singbox_current_version=$(singbox_version_of "$singbox_binary")
  singbox_target_version=${SINGBOX_VERSION#v}
  if [ "$singbox_current_version" = "$singbox_target_version" ]; then info "sing-box 已是 $singbox_target_version，无需更新"; return 0; fi
  download_singbox_binary
  prepare_singbox_configs
  info "用新版本检查全部迁移后配置"
  check_singbox_configs "$SINGBOX_CANDIDATE" "$SINGBOX_MIGRATED_DIR" || die "迁移后配置仍与新版本不兼容，未修改任何文件"
  singbox_services_file="$TMP_DIR/singbox-active-services"
  capture_active_singbox_services "$singbox_services_file" "$singbox_binary"
  [ -s "$singbox_services_file" ] || die "未检测到正在运行的 sing-box 服务，已拒绝更新；请先恢复节点服务"
  singbox_backup_dir=$(backup_singbox update "$singbox_binary" "$singbox_services_file")
  persist_singbox_transaction "$singbox_backup_dir" "$singbox_binary"
  stop_singbox_services "$singbox_services_file" || die "无法停止全部 sing-box 服务，正在恢复升级前状态"
  install_singbox_configs "$SINGBOX_MIGRATED_DIR" || die "安装迁移配置失败，正在恢复升级前状态"
  install -m 0755 "$SINGBOX_CANDIDATE" "$singbox_binary" || die "替换 sing-box 二进制失败，正在恢复升级前状态"
  if check_singbox_configs "$singbox_binary" && start_singbox_services "$singbox_services_file" && probe_singbox_nodes "$singbox_binary"; then
    rm -f /var/lib/wukong-panel/backups/sing-box/previous
    ln -s "$singbox_backup_dir" /var/lib/wukong-panel/backups/sing-box/previous
    clear_singbox_transaction
    info "sing-box 已从 ${singbox_current_version:-unknown} 更新到 $singbox_target_version"
    info "旧版本备份：$singbox_backup_dir"
    return 0
  fi
  die "sing-box 更新失败，正在自动恢复 ${singbox_current_version:-unknown} 与原活动服务"
}

rollback_singbox() {
  rollback_binary=$(singbox_binary_path)
  [ -x "$rollback_binary" ] || die "未找到 sing-box 二进制：$rollback_binary"
  if [ -e "$SINGBOX_TRANSACTION_ROOT" ]; then
    recover_pending_singbox_transaction
    info "未完成事务已恢复，本次无需再执行额外回退"
    return 0
  fi
  rollback_backup_root=/var/lib/wukong-panel/backups/sing-box
  rollback_previous=$(readlink "$rollback_backup_root/previous" 2>/dev/null || true)
  [ -n "$rollback_previous" ] && [ -x "$rollback_previous/sing-box" ] || die "没有可回退的 sing-box 备份"
  [ -d "$rollback_previous/configs" ] || die "回退备份缺少配置快照"
  verify_singbox_backup "$rollback_previous" || die "回退备份校验和不匹配，已拒绝使用"
  prepare_singbox_migrator
  rollback_version=$(singbox_version_of "$rollback_previous/sing-box")
  info "用备份版本检查配套配置快照"
  check_singbox_configs "$rollback_previous/sing-box" "$rollback_previous/configs" || die "备份中的二进制与配置快照不匹配，已拒绝回退"
  rollback_services_file="$TMP_DIR/singbox-active-services"
  capture_active_singbox_services "$rollback_services_file" "$rollback_binary"
  rollback_current_backup=$(backup_singbox rollback "$rollback_binary" "$rollback_services_file")
  if ! stop_singbox_services "$rollback_services_file"; then start_singbox_services "$rollback_services_file" || true; die "无法停止全部 sing-box 服务，已取消回退"; fi
  restore_singbox_configs "$rollback_previous/configs"
  if ! install -m 0755 "$rollback_previous/sing-box" "$rollback_binary"; then
    install -m 0755 "$rollback_current_backup/sing-box" "$rollback_binary" || true
    restore_singbox_configs "$rollback_current_backup/configs" || true
    start_singbox_services "$rollback_services_file" || true
    die "替换 sing-box 二进制失败，已恢复操作前版本"
  fi
  rollback_target_services="$rollback_previous/active-services"
  [ -f "$rollback_target_services" ] || rollback_target_services="$rollback_services_file"
  if check_singbox_configs "$rollback_binary" && start_singbox_services "$rollback_target_services" && probe_singbox_nodes "$rollback_binary"; then
    rm -f "$rollback_backup_root/previous"
    ln -s "$rollback_current_backup" "$rollback_backup_root/previous"
    info "sing-box 已回退到 ${rollback_version:-unknown}"
    info "刚才版本已保留：$rollback_current_backup"
    return 0
  fi
  warn "回退版本启动失败，正在恢复当前版本"
  stop_singbox_services "$rollback_services_file" || true
  install -m 0755 "$rollback_current_backup/sing-box" "$rollback_binary"
  restore_singbox_configs "$rollback_current_backup/configs"
  start_singbox_services "$rollback_services_file" || true
  die "sing-box 回退失败，已恢复操作前版本"
}

usage() {
  cat <<'EOF'
悟空面板安装器

用法：
  sh install.sh [参数]
  curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- [参数]

常用参数：
  --action ACTION      install、update、reset-password、uninstall、singbox-update、singbox-rollback 或 singbox-uninstall
  --update             等同于 --action update
  --reset-password     重置 admin 密码、撤销会话并强制首次登录改密
  --update-sing-box    更新到悟空验证过的 sing-box 稳定版本
  --rollback-sing-box  回退到上一次保留的 sing-box 版本
  --uninstall-sing-box 备份后卸载 sing-box 二进制、JSON 配置和节点服务
  --sing-box-version VERSION  指定悟空支持的 sing-box 版本
  --uninstall          等同于 --action uninstall
  --purge              卸载时同时删除面板配置和数据
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
    --action) ACTION="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --update) ACTION=update; HAS_CONFIG_ARGS=true; shift ;;
    --reset-password) ACTION=reset-password; HAS_CONFIG_ARGS=true; shift ;;
    --update-sing-box) ACTION=singbox-update; HAS_CONFIG_ARGS=true; shift ;;
    --rollback-sing-box) ACTION=singbox-rollback; HAS_CONFIG_ARGS=true; shift ;;
    --uninstall-sing-box) ACTION=singbox-uninstall; HAS_CONFIG_ARGS=true; shift ;;
    --sing-box-version) ACTION=singbox-update; SINGBOX_VERSION="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --uninstall) ACTION=uninstall; HAS_CONFIG_ARGS=true; shift ;;
    --purge) ACTION=uninstall; PURGE=true; HAS_CONFIG_ARGS=true; shift ;;
    --version) VERSION="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --domain) DOMAIN="$2"; DOMAIN_SET=true; HAS_CONFIG_ARGS=true; RECONFIGURE_ARGS=true; shift 2 ;;
    --port) PORT="$2"; PORT_SET=true; HAS_CONFIG_ARGS=true; RECONFIGURE_ARGS=true; shift 2 ;;
    --base-path) BASE_PATH="$2"; HAS_CONFIG_ARGS=true; RECONFIGURE_ARGS=true; shift 2 ;;
    --acme) ACME_METHOD="$2"; ACME_SET=true; HAS_CONFIG_ARGS=true; RECONFIGURE_ARGS=true; shift 2 ;;
    --acme-ip-version) ACME_IP_VERSION="$2"; HAS_CONFIG_ARGS=true; RECONFIGURE_ARGS=true; shift 2 ;;
    --cert-file) CERT_FILE="$2"; HAS_CONFIG_ARGS=true; RECONFIGURE_ARGS=true; shift 2 ;;
    --key-file) KEY_FILE="$2"; HAS_CONFIG_ARGS=true; RECONFIGURE_ARGS=true; shift 2 ;;
    --email) EMAIL="$2"; EMAIL_SET=true; HAS_CONFIG_ARGS=true; RECONFIGURE_ARGS=true; shift 2 ;;
    --binary) BINARY_SOURCE="$2"; HAS_CONFIG_ARGS=true; shift 2 ;;
    --interactive) FORCE_INTERACTIVE=true; shift ;;
    --unattended|-y|--yes) UNATTENDED=true; shift ;;
    --skip-packages) SKIP_PACKAGES=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "请使用 root 或 sudo 执行安装器"
PROMPT_TTY=$(detect_prompt_tty)

INTERACTIVE_SESSION=false
if interactive_available; then
  INTERACTIVE_SESSION=true
  if [ "$ACTION" = "auto" ]; then
    if panel_installed; then
      printf '%s\n' "检测到已安装悟空面板，请选择操作：" "  1) 更新悟空面板" "  2) 更新 sing-box（保留旧版，可回退）" "  3) 回退 sing-box 到上一版本" "  4) 卸载 sing-box（先完整备份节点）" "  5) 重置面板 admin 密码" "  6) 重新配置 / 修复安装" "  7) 卸载面板（保留配置和数据）" "  8) 完全卸载（删除面板配置和数据）" "  9) 取消" >"$PROMPT_TTY"
      action_choice=$(prompt_value "选择" "1")
      case "$action_choice" in 1|update) ACTION=update ;; 2|singbox-update) ACTION=singbox-update ;; 3|singbox-rollback) ACTION=singbox-rollback ;; 4|singbox-uninstall) ACTION=singbox-uninstall ;; 5|reset-password) ACTION=reset-password ;; 6|install|repair) ACTION=install ;; 7|uninstall) ACTION=uninstall ;; 8|purge) ACTION=uninstall; PURGE=true ;; 9|cancel) info "已取消"; exit 0 ;; *) die "无效的操作选项: $action_choice" ;; esac
    else
      printf '%s\n' "请选择操作：" "  1) 安装悟空面板" "  2) 取消" >"$PROMPT_TTY"
      action_choice=$(prompt_value "选择" "1")
      case "$action_choice" in 1|install) ACTION=install ;; 2|cancel) info "已取消"; exit 0 ;; *) die "无效的操作选项: $action_choice" ;; esac
    fi
  fi
fi

if [ "$ACTION" = "auto" ]; then
  installed=false
  panel_installed && installed=true
  ACTION=$(resolve_auto_action "$installed" "$RECONFIGURE_ARGS")
fi
case "$ACTION" in install|update|reset-password|uninstall|singbox-update|singbox-rollback|singbox-uninstall) ;; *) die "--action 必须是 install、update、reset-password、uninstall、singbox-update、singbox-rollback 或 singbox-uninstall" ;; esac

if [ "$ACTION" = "uninstall" ]; then
  if [ "$INTERACTIVE_SESSION" = true ]; then
    if [ "$PURGE" = true ]; then uninstall_scope="程序、配置和数据"; else uninstall_scope="程序（保留配置和数据）"; fi
    confirm_uninstall=$(prompt_value "确认卸载${uninstall_scope}？(y/N)" "N")
    case "$confirm_uninstall" in Y|y|yes|YES|Yes) ;; *) info "已取消卸载"; exit 0 ;; esac
  fi
  uninstall_panel "$PURGE"
  exit 0
fi

case "$ACTION" in
  update|reset-password|singbox-update|singbox-rollback|singbox-uninstall) panel_installed || die "未检测到已安装的悟空面板，无法执行该操作" ;;
esac

if [ "$INTERACTIVE_SESSION" = true ] && [ "$ACTION" = "singbox-uninstall" ]; then
  confirm_singbox_uninstall=$(prompt_value "确认备份后卸载 sing-box、全部节点 JSON 和服务定义？(y/N)" "N")
  case "$confirm_singbox_uninstall" in Y|y|yes|YES|Yes) ;; *) info "已取消 sing-box 卸载"; exit 0 ;; esac
fi

if [ "$INTERACTIVE_SESSION" = true ] && [ "$ACTION" = "singbox-rollback" ]; then
  previous_path=$(readlink /var/lib/wukong-panel/backups/sing-box/previous 2>/dev/null || true)
  previous_version=""
  [ -z "$previous_path" ] || previous_version=$(singbox_version_of "$previous_path/sing-box")
  [ -n "$previous_version" ] || die "没有可回退的 sing-box 备份"
  confirm_singbox=$(prompt_value "确认回退 sing-box 到 $previous_version？(y/N)" "N")
  case "$confirm_singbox" in Y|y|yes|YES|Yes) ;; *) info "已取消 sing-box 回退"; exit 0 ;; esac
fi

if [ "$ACTION" = "install" ] && [ "$INTERACTIVE_SESSION" = true ]; then
  info "进入交互安装向导（直接回车采用默认值）"
  if [ "$DOMAIN_SET" != true ]; then
    DOMAIN=$(prompt_value "面板域名（留空则使用 IP 和自签名证书）" "$DOMAIN")
  fi
  if [ "$PORT_SET" != true ]; then
    PORT=$(prompt_value "面板 HTTPS 端口" "$PORT")
  fi
  if [ -n "$DOMAIN" ] && [ "$ACME_SET" != true ]; then
    printf '%s\n' "请选择 TLS 证书方式：" "  1) Let's Encrypt HTTP-01（推荐，域名需指向本机且公网 80 可达）" "  2) Let's Encrypt Cloudflare DNS-01" "  3) 自签名证书" >"$PROMPT_TTY"
    cert_choice=$(prompt_value "选择" "1")
    case "$cert_choice" in 1|http) ACME_METHOD=http ;; 2|cloudflare) ACME_METHOD=cloudflare ;; 3|selfsigned) ACME_METHOD=selfsigned ;; *) die "无效的证书方式选项: $cert_choice" ;; esac
  fi
  if [ "$ACME_METHOD" = "http" ] && [ -z "$ACME_IP_VERSION" ]; then
    printf '%s\n' "请选择 HTTP-01 验证网络：" "  1) 自动选择" "  2) 仅 IPv4" "  3) 仅 IPv6（适合 IPv4 NAT 端口受限的 VPS）" >"$PROMPT_TTY"
    ip_choice=$(prompt_value "选择" "1")
    case "$ip_choice" in 1|auto) ACME_IP_VERSION="" ;; 2|4) ACME_IP_VERSION=4 ;; 3|6) ACME_IP_VERSION=6 ;; *) die "无效的 IP 版本选项: $ip_choice" ;; esac
  fi
  if { [ "$ACME_METHOD" = "http" ] || [ "$ACME_METHOD" = "cloudflare" ]; } && [ "$EMAIL_SET" != true ]; then
    email_default="admin@$(printf '%s' "$DOMAIN" | cut -d. -f2-)"
    EMAIL=$(prompt_value "Let's Encrypt 账户邮箱" "$email_default")
  fi
  printf '\n安装配置确认\n  域名: %s\n  HTTPS 端口: %s\n  证书方式: %s\n  HTTP-01 网络: %s\n\n' "${DOMAIN:-不使用域名}" "$PORT" "$ACME_METHOD" "${ACME_IP_VERSION:-自动/不适用}" >"$PROMPT_TTY"
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

TMP_DIR=$(mktemp -d)
cleanup_install() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM
  if [ "$SINGBOX_TRANSACTION_ACTIVE" = true ]; then
    rollback_singbox_transaction || warn "自动回滚未完成，请保留终端并人工检查 $SINGBOX_TRANSACTION_ROOT"
  fi
  rm -rf "$TMP_DIR"
  exit "$cleanup_status"
}
trap 'cleanup_install' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$ACTION" = "update" ]; then
  update_panel
  exit 0
fi
if [ "$ACTION" = "reset-password" ]; then
  reset_panel_password
  exit 0
fi
if [ "$ACTION" = "singbox-update" ]; then
  update_singbox
  exit 0
fi
if [ "$ACTION" = "singbox-rollback" ]; then
  rollback_singbox
  exit 0
fi
if [ "$ACTION" = "singbox-uninstall" ]; then
  uninstall_singbox
  exit 0
fi

if [ "$SKIP_PACKAGES" != true ]; then
  info "安装运行依赖（$OS_ID / $INIT）"
  case "$FAMILY" in
    apt) apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl openssl nginx tcpdump tar >/dev/null ;;
    dnf) dnf install -y -q ca-certificates curl openssl nginx tcpdump shadow-utils tar >/dev/null ;;
    apk) apk add -q ca-certificates curl openssl nginx tcpdump tar ;;
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

ensure_singbox_for_install

if [ -z "$BASE_PATH" ] && [ -r /etc/wukong-panel/env ]; then
  BASE_PATH=$(sed -n 's/^WUKONG_BASE_PATH=//p' /etc/wukong-panel/env | head -1)
fi
if [ -z "$BASE_PATH" ]; then BASE_PATH="/wukong-$(openssl rand -hex 12)/"; fi
case "$BASE_PATH" in /*) ;; *) BASE_PATH="/$BASE_PATH" ;; esac
case "$BASE_PATH" in */) ;; *) BASE_PATH="$BASE_PATH/" ;; esac

download_panel_binary
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
  ACME_ISSUE_STATUS=0
  if [ "$ACME_METHOD" = "http" ]; then
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:|\])80$'; then die "公网 80 已被占用；请改用 --acme cloudflare 或导入现有证书"; fi
    info "申请 Let's Encrypt 证书（HTTP-01${ACME_IP_VERSION:+ / IPv$ACME_IP_VERSION}）"
    case "$ACME_IP_VERSION" in
      4) /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --listen-v4 --httpport 80 --keylength ec-256 --server letsencrypt || ACME_ISSUE_STATUS=$? ;;
      6) /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --listen-v6 --httpport 80 --keylength ec-256 --server letsencrypt || ACME_ISSUE_STATUS=$? ;;
      *) /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --httpport 80 --keylength ec-256 --server letsencrypt || ACME_ISSUE_STATUS=$? ;;
    esac
  else
    [ -n "${CF_Token:-}" ] || die "Cloudflare DNS-01 需要 CF_Token"
    [ -n "${CF_Zone_ID:-${CF_Account_ID:-}}" ] || die "Cloudflare DNS-01 还需要 CF_Zone_ID 或 CF_Account_ID"
    /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --dns dns_cf --keylength ec-256 --server letsencrypt || ACME_ISSUE_STATUS=$?
  fi
  accept_acme_issue_status "$ACME_ISSUE_STATUS"
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
WUKONG_SINGBOX_CONFIG_DIR=$SINGBOX_RUNTIME_CONFIG_DIR
WUKONG_SINGBOX_BIN=$SINGBOX_RUNTIME_BIN
WUKONG_TLS_CERT=$TLS_CERT
WUKONG_TLS_KEY=$TLS_KEY
WUKONG_PANEL_DOMAIN=$DOMAIN
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
set -a
. /etc/wukong-panel/env
set +a
depend() { need net; }
EOF
  cat > /etc/init.d/wukong-web <<'EOF'
#!/sbin/openrc-run
name="Wukong Panel Web"
command="/usr/local/bin/wukong-panel"
command_args="web"
command_user="wukong:wukong"
command_background=true
pidfile="/run/wukong-panel/web.pid"
output_log="/var/log/wukong-web.log"
error_log="/var/log/wukong-web.log"
set -a
. /etc/wukong-panel/env
set +a
depend() { need net wukong-agent; }
EOF
  chmod 0755 /etc/init.d/wukong-agent /etc/init.d/wukong-web
  rc-update add wukong-agent default >/dev/null
  rc-update add wukong-web default >/dev/null
  rc-service wukong-agent restart
  rc-service wukong-web restart
fi

if ! wait_for_web >/dev/null; then
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

if [ "$ACME_METHOD" = "http" ] || [ "$ACME_METHOD" = "cloudflare" ]; then
  configure_certificate_renewal "$DOMAIN" "$TLS_CERT" "$TLS_KEY"
fi

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
