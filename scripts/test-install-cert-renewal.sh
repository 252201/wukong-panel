#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf "$TMP"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

awk '
  /cat > "\$reload_hook" <<'"'"'EOF_WUKONG_CERT_RELOAD'"'"'/ { capture = 1; next }
  capture && /^EOF_WUKONG_CERT_RELOAD$/ { exit }
  capture { print }
' "$ROOT/install.sh" > "$TMP/wukong-cert-reload"
awk '
  /cat > "\$renew_hook" <<'"'"'EOF_WUKONG_CERT_RENEW'"'"'/ { capture = 1; next }
  capture && /^EOF_WUKONG_CERT_RENEW$/ { exit }
  capture { print }
' "$ROOT/install.sh" > "$TMP/wukong-cert-renew"

[ -s "$TMP/wukong-cert-reload" ] || { echo "certificate reload hook missing" >&2; exit 1; }
[ -s "$TMP/wukong-cert-renew" ] || { echo "certificate renewal hook missing" >&2; exit 1; }
sh -n "$TMP/wukong-cert-reload" "$TMP/wukong-cert-renew"

grep -Fq '"$singbox_bin" check -c "$config"' "$TMP/wukong-cert-reload"
grep -Fq 'grep -F "$tls_cert" "$config"' "$TMP/wukong-cert-reload"
grep -Fq 'systemctl reload nginx.service' "$TMP/wukong-cert-reload"
grep -Fq 'rc-service nginx reload' "$TMP/wukong-cert-reload"
grep -Fq 'Le_Webroot' "$TMP/wukong-cert-renew"
grep -Fq '"$acme" --cron --home "$acme_home"' "$TMP/wukong-cert-renew"

grep -Fq 'Persistent=true' "$ROOT/install.sh"
grep -Fq 'RandomizedDelaySec=40m' "$ROOT/install.sh"
grep -Fq '/etc/periodic/daily/wukong-cert-renew' "$ROOT/install.sh"
grep -Fq -- '--uninstall-cronjob' "$ROOT/install.sh"
grep -Fq 'backfill_certificate_renewal' "$ROOT/install.sh"

mkdir -p "$TMP/bin" "$TMP/acme/example.com_ecc" "$TMP/configs"
cat > "$TMP/bin/systemctl" <<'EOF'
#!/bin/sh
printf 'systemctl:%s\n' "$*" >> "$WUKONG_TEST_LOG"
case "$1" in is-active) exit 0 ;; esac
exit 0
EOF
cat > "$TMP/bin/nginx" <<'EOF'
#!/bin/sh
printf 'nginx:%s\n' "$*" >> "$WUKONG_TEST_LOG"
exit 0
EOF
cat > "$TMP/bin/rc-service" <<'EOF'
#!/bin/sh
printf 'rc-service:%s\n' "$*" >> "$WUKONG_TEST_LOG"
exit 0
EOF
cat > "$TMP/acme/acme.sh" <<'EOF'
#!/bin/sh
printf 'acme:%s\n' "$*" >> "$WUKONG_TEST_LOG"
exit "${WUKONG_TEST_ACME_EXIT:-0}"
EOF
chmod 0755 "$TMP/bin/systemctl" "$TMP/bin/nginx" "$TMP/bin/rc-service" "$TMP/acme/acme.sh"

cat > "$TMP/acme/example.com_ecc/example.com.conf" <<'EOF'
Le_Webroot='no'
Le_NextRenewTime='0'
EOF
: > "$TMP/renew.log"
PATH="$TMP/bin:$PATH" WUKONG_TEST_LOG="$TMP/renew.log" WUKONG_ACME_HOME="$TMP/acme" sh "$TMP/wukong-cert-renew"
grep -Fqx 'systemctl:stop nginx.service' "$TMP/renew.log"
grep -Fqx 'systemctl:start nginx.service' "$TMP/renew.log"
grep -Fqx "acme:--cron --home $TMP/acme" "$TMP/renew.log"

cat > "$TMP/acme/example.com_ecc/example.com.conf" <<'EOF'
Le_Webroot='dns_cf'
Le_NextRenewTime='0'
EOF
: > "$TMP/renew.log"
PATH="$TMP/bin:$PATH" WUKONG_TEST_LOG="$TMP/renew.log" WUKONG_ACME_HOME="$TMP/acme" sh "$TMP/wukong-cert-renew"
! grep -q 'systemctl:stop nginx.service' "$TMP/renew.log"
! grep -q 'systemctl:start nginx.service' "$TMP/renew.log"

cat > "$TMP/acme/example.com_ecc/example.com.conf" <<'EOF'
Le_Webroot='no'
Le_NextRenewTime='0'
EOF
: > "$TMP/renew.log"
if PATH="$TMP/bin:$PATH" WUKONG_TEST_LOG="$TMP/renew.log" WUKONG_TEST_ACME_EXIT=9 WUKONG_ACME_HOME="$TMP/acme" sh "$TMP/wukong-cert-renew"; then
  echo "failed ACME renewal returned success" >&2
  exit 1
fi
grep -Fqx 'systemctl:start nginx.service' "$TMP/renew.log"

touch "$TMP/fullchain.cer"
cat > "$TMP/configs/node.json" <<EOF
{"inbounds":[{"tls":{"certificate_path":"$TMP/fullchain.cer"}}]}
EOF
cat > "$TMP/sing-box" <<'EOF'
#!/bin/sh
printf 'sing-box:%s\n' "$*" >> "$WUKONG_TEST_LOG"
exit 0
EOF
chmod 0755 "$TMP/sing-box"
cat > "$TMP/env" <<EOF
WUKONG_TLS_CERT=$TMP/fullchain.cer
WUKONG_SINGBOX_CONFIG_DIR=$TMP/configs
WUKONG_SINGBOX_BIN=$TMP/sing-box
EOF
: > "$TMP/reload.log"
PATH="$TMP/bin:$PATH" WUKONG_TEST_LOG="$TMP/reload.log" WUKONG_ENV_FILE="$TMP/env" sh "$TMP/wukong-cert-reload"
grep -Fqx "sing-box:check -c $TMP/configs/node.json" "$TMP/reload.log"
grep -Fqx 'nginx:-t' "$TMP/reload.log"
grep -Fqx 'systemctl:reload nginx.service' "$TMP/reload.log"

echo "installer certificate renewal: ok"
