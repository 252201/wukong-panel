# 悟空面板 CLI 与 API 指南

悟空面板随程序分发统一命令行工具 `wukongctl`（与 `wukong-panel` 指向同一静态二进制），并提供标准 RESTful HTTP API。

---

## 命令行工具 (CLI)

### 组件更新与日常维护
```bash
# 查看命令行工具帮助菜单
wukongctl --help

# 升级面板主程序（通过本地 Unix Socket 或管理器一键更新）
sudo wukongctl update

# 升级 sing-box 代理内核
sudo wukongctl update sing-box

# 升级 Cloudflare Tunnel 连接器
sudo wukongctl update cloudflared

# 重置管理员密码并撤销所有现有会话
sudo wukongctl reset-password
```

### 系统自检与节点扫描
```bash
# 检查当前环境运行依赖、端口与服务状态
wukongctl doctor

# 扫描本地已有的 /etc/s-box 目录与 systemd/OpenRC 节点配置
wukongctl scan
```

### 节点创建命令示例
```bash
# 创建 Hysteria 2 节点
wukongctl node create --name "Node-HY2" --server node.example.com --domain node.example.com --mode prefer_v6

# 创建 VLESS + REALITY 节点
wukongctl node create --protocol vless --name "Node-Reality" --server node.example.com --domain s0.awsstatic.com --mode prefer_v6

# 创建 VLESS + WS + Cloudflare Tunnel 节点
wukongctl node create --protocol vless-ws-tunnel --name "Node-CF-WS" --server edge.example.com --ws-path /wukong-edge --tunnel-token-file /root/cloudflare-tunnel.token

# 创建 Shadowsocks 2022 节点
wukongctl node create --protocol shadowsocks --name "Node-SS2022" --server node.example.com --mode prefer_v6

# 创建 TUIC v5 节点
wukongctl node create --protocol tuic --name "Node-TUIC" --server node.example.com --domain node.example.com --mode prefer_v6

# 创建 Trojan TLS 节点
wukongctl node create --protocol trojan --name "Node-Trojan" --server node.example.com --domain node.example.com --mode prefer_v6

# 创建 AnyTLS 节点
wukongctl node create --protocol anytls --name "Node-AnyTLS" --server node.example.com --domain node.example.com --mode prefer_v6
```

### 节点操作与连通性自检
```bash
# 重启指定节点
wukongctl node action --id NODE_ID --action restart

# 本机闭环自检指定节点（验证配置、握手、认证与代理出站）
wukongctl node action --id NODE_ID --action probe
```

---

## RESTful API 概览

管理 API 均以 `/api/v1` 为基础路径，变更类 API 均校验 CSRF 并支持通过 Task ID 异步跟踪事件进度：

- **认证与会话**：`/api/v1/auth/login`、`me`、`password`、`logout`
- **监控与大盘**：`/api/v1/overview`、`metrics`、`metrics/endpoints`、`metrics/timeline`
- **节点管理**：`/api/v1/nodes`、`nodes/batch`、`nodes/{id}/actions`、`nodes/{id}/share`
- **配置接管**：`/api/v1/imports/scan`、`imports/confirm`
- **系统与迁移**：`/api/v1/system/sing-box/migration`、`system/residential-exit`
- **任务调度**：`/api/v1/jobs`、`jobs/{id}/events`
- **中央舰队与订阅**：`/api/v1/settings`、`/api/v1/settings/subscription-token`、`/api/v1/fleet/hosts/{id}/quota`

客户端 Clash/Mihomo 订阅入口与管理后台完全隔离，固定格式为 `/sub/{token}/clash.yaml`。
