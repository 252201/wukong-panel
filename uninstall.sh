#!/bin/sh
set -eu
PURGE=false
[ "${1:-}" = "--purge" ] && PURGE=true
[ "$(id -u)" -eq 0 ] || { echo "请使用 sudo/root" >&2; exit 1; }
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now wukong-web.service wukong-agent.service 2>/dev/null || true
  rm -f /etc/systemd/system/wukong-web.service /etc/systemd/system/wukong-agent.service
  systemctl daemon-reload
else
  rc-service wukong-web stop 2>/dev/null || true; rc-service wukong-agent stop 2>/dev/null || true
  rc-update del wukong-web default 2>/dev/null || true; rc-update del wukong-agent default 2>/dev/null || true
  rm -f /etc/init.d/wukong-web /etc/init.d/wukong-agent
fi
rm -f /etc/nginx/conf.d/wukong-panel.conf /etc/nginx/http.d/wukong-panel.conf /usr/local/bin/wukong-panel /usr/local/bin/wukongctl
nginx -t >/dev/null 2>&1 && { command -v systemctl >/dev/null 2>&1 && systemctl reload nginx || rc-service nginx reload; } || true
if [ "$PURGE" = true ]; then rm -rf /var/lib/wukong-panel /etc/wukong-panel; else echo "已保留 /var/lib/wukong-panel 与 /etc/wukong-panel；使用 --purge 才会删除数据。"; fi
echo "悟空面板已卸载，sing-box 节点和配置未改动。"
