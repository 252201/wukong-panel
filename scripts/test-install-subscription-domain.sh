#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
INSTALLER="$ROOT/install.sh"

sh -n "$INSTALLER"
grep -Fq -- '--configure-subscription-domain DOMAIN' "$INSTALLER"
grep -Fq 'location ^~ /fleet-sub/' "$INSTALLER"
grep -Fq 'location / { return 404; }' "$INSTALLER"
grep -Fq 'proxy_pass http://127.0.0.1:8788;' "$INSTALLER"
grep -Fq 'limit_except GET { deny all; }' "$INSTALLER"
grep -Fq '# Managed by Wukong Panel subscription gateway' "$INSTALLER"
grep -Fq '订阅域名已由其他 Nginx 配置使用' "$INSTALLER"
grep -Fq '订阅专用 Nginx 无法启动或重载，已恢复原配置' "$INSTALLER"
grep -Fq 'openssl x509 -in "$subscription_tls_cert" -noout -checkhost "$subscription_domain"' "$INSTALLER"
grep -Fq 'configure_certificate_renewal "$subscription_domain"' "$INSTALLER"
grep -Fq '请确认云安全组与本机防火墙允许 443/tcp' "$INSTALLER"

help_output=$(sh "$INSTALLER" --help)
printf '%s\n' "$help_output" | grep -Fq '独立订阅 443 域名示例'

printf '%s\n' 'subscription domain installer checks passed'
