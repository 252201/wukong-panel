#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FUNCTION_BODY=$(awk '
  /^backfill_panel_tls\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$ROOT/install.sh")
[ -n "$FUNCTION_BODY" ] || { echo "backfill_panel_tls not found" >&2; exit 1; }
eval "$FUNCTION_BODY"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$TMP/tls/private.key" -out "$TMP/tls/fullchain.cer" \
  -subj '/CN=panel.example.com' -addext 'subjectAltName=DNS:panel.example.com' >/dev/null 2>&1
cat > "$TMP/env" <<'EOF'
WUKONG_PANEL_DOMAIN=panel.example.com
EOF
cat > "$TMP/nginx.conf" <<EOF
server {
  server_name panel.example.com;
  ssl_certificate $TMP/tls/fullchain.cer;
  ssl_certificate_key $TMP/tls/private.key;
}
EOF
info() { :; }
warn() { :; }

backfill_panel_tls "$TMP/env" "$TMP/nginx.conf"
grep -Fqx "WUKONG_TLS_CERT=$TMP/tls/fullchain.cer" "$TMP/env"
grep -Fqx "WUKONG_TLS_KEY=$TMP/tls/private.key" "$TMP/env"

backfill_panel_tls "$TMP/env" "$TMP/nginx.conf"
[ "$(grep -c '^WUKONG_TLS_CERT=' "$TMP/env")" -eq 1 ]
[ "$(grep -c '^WUKONG_TLS_KEY=' "$TMP/env")" -eq 1 ]

cat > "$TMP/wrong-env" <<'EOF'
WUKONG_PANEL_DOMAIN=other.example.com
EOF
backfill_panel_tls "$TMP/wrong-env" "$TMP/nginx.conf"
! grep -q '^WUKONG_TLS_CERT=' "$TMP/wrong-env"
! grep -q '^WUKONG_TLS_KEY=' "$TMP/wrong-env"

echo "installer TLS backfill: ok"
