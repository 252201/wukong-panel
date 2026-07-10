#!/bin/sh
# Compatibility bridge for the historical deploy-hy2.sh CLI.
# Interactive and uninstall workflows should continue to use the archived legacy script.
set -eu

command -v wukongctl >/dev/null 2>&1 || { echo "请先安装悟空面板，或使用 deploy-hy2-legacy.sh" >&2; exit 1; }
[ "$#" -gt 0 ] || { echo "悟空兼容入口仅支持参数模式；交互模式请在面板中使用“部署节点”" >&2; exit 1; }

for argument in "$@"; do
  [ "$argument" != "--uninstall" ] || { echo "请运行悟空面板 uninstall.sh；默认保留 sing-box 节点" >&2; exit 2; }
done

exec wukongctl node create "$@"
