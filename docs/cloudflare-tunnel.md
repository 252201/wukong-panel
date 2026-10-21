# VLESS + WebSocket + Cloudflare Tunnel 节点与设备编队指南

悟空面板原生支持通过 Cloudflare Zero Trust Tunnel 承载 VLESS + WebSocket 流量。该方案将 VPS 的入站流量安全隐藏在 Cloudflare 边缘之后，无需在 VPS 防火墙或公网开放任何入站端口，亦无需将 Cloudflare API Key 授予面板。

---

## 核心特性

- **零公网端口暴露**：sing-box 仅在本地回环地址（`127.0.0.1`）监听 Origin 端口，公网入站由 `cloudflared` 连接器代理至 Cloudflare 边缘网络（`443/TLS`）。
- **设备编队单进程多 Inbound**：单组 2–20 台设备仅需运行一个共享 sing-box 进程和一个 `cloudflared` 连接器，由多条 Published application 独立路由，资源消耗极低。
- **优选接入 IP / 域名**：支持配置 Cloudflare 优选节点地址，仅替换客户端连接目标，不改变 TLS SNI 与 WebSocket Host。
- **连接器生命周期管理**：面板支持检查、下载并自动更新官方稳定版 `cloudflared`，提供故障自动回滚。

---

## 配置步骤

### 1. 在 Cloudflare 创建 Tunnel
1. 登录 Cloudflare Zero Trust 控制台，导航至 **Networks → Tunnels**。
2. 创建一个新的 Remotely-managed Tunnel（选择 `cloudflared` 类型）。
3. 在安装命令步骤中，仅复制运行命令中的 **Token**（例如一长串 Base64 字符串）。

### 2. 在面板部署节点
- **单节点部署**：在节点列表点击“部署节点”，协议选择 `VLESS + WebSocket + Cloudflare Tunnel`。
- **设备编队部署**：点击右上角“设备专用节点”，协议选择 `VLESS + WebSocket + Cloudflare Tunnel`，输入设备数量（2–20 台）。
- 填入公开节点域名（如 `node.example.com`）并粘贴 Tunnel Token。
- 本地 Origin 端口与 VLESS UUID 将自动生成；WebSocket 路径建议留空由面板自动随机生成。

### 3. 配置 Cloudflare Published Application 路由
1. 部署完成后，从节点卡片（或设备卡片）复制对应的本地 Service URL（如 `http://127.0.0.1:41234`）。
2. 返回 Cloudflare 刚才创建的 Tunnel 配置页，进入 **Public Hostname / Published applications**。
3. 为每个节点（或编队中的每台设备）添加一条规则：
   - **Subdomain / Domain**：填入对应的公开主机名。
   - **Path**：保持留空（WebSocket 路径已内置于客户端订阅）。
   - **Service Type**：`HTTP`。
   - **URL**：粘贴对应的 `127.0.0.1:<端口>`。
4. 保存配置，节点即可通过 Cloudflare CDN 全球加速与边缘 TLS 连通。

---

## 优选连接域名 / IP
若测得更适合当前本地运营商的 Cloudflare 优选 IP 或域名，可在部署或编辑节点时填入“优选连接域名 / IP”：
- 面板仅将该地址写入客户端分享链接与 Clash/Mihomo 订阅的 `server` 字段；
- TLS `servername`、SNI、WebSocket `Host` 保持原 Cloudflare 节点域名不变；
- 该字段禁止包含协议前缀（如 `https://`）或路径。
