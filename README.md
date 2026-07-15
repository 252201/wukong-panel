# 悟空面板

悟空面板是面向个人与小型团队的单机 VPS 节点控制台，将 Hysteria2、VLESS + REALITY、VLESS + WebSocket + Cloudflare Tunnel、Shadowsocks 2022、TUIC v5、Trojan TLS 的部署、生命周期管理、分享订阅、主机状态和整机流量账期放在同一个安全界面中。

![Version](https://img.shields.io/badge/version-v0.6.3-d4ad57)
![Go](https://img.shields.io/badge/Go-1.24+-52b690)
![Vue](https://img.shields.io/badge/Vue-3.5-52b690)

## 特性

- 单机自治：每台 VPS 独立安装，无需中心服务器。
- 六协议驱动：完整管理 Hysteria2、VLESS + REALITY、VLESS + WebSocket + Cloudflare Tunnel、Shadowsocks 2022、TUIC v5 与 Trojan TLS；支持 IPv6 优先、纯 IPv4、纯 IPv6、NAT 本地绑定、设备专用节点与无中断重命名。普通节点与设备编队使用相互独立的右上角入口；设备专用入口可一次创建 2–20 台设备，每台设备使用独立端口、凭据、服务与分享配置。新建 REALITY 节点默认使用已验证的 `www.cloudflare.com` 握手目标并继续自动分配随机端口，已有节点不会被改写。
- 安全凭据：自动生成 UUID、WebSocket 随机路径、REALITY X25519 密钥、Short ID、SS2022 定长密钥和协议密码；Tunnel Token 不进入分享链接或公开 API，只以 AES-256-GCM 密文和 root-only `0600` 运行文件保存。
- Cloudflare 优选接入：Tunnel 节点可选填优选域名或 IP，仅替换客户端实际拨号地址；TLS SNI、WebSocket Host 与 Published application 主机名保持不变。
- 安全管理：非特权 Web 服务与 root Agent 通过受限 Unix Socket 通信。
- 无损接管：扫描 `/etc/s-box` 与 systemd/OpenRC 服务，确认后导入，不重写未知字段。
- 安全变更：配置暂存、`sing-box check`、原子替换、SHA-256 快照与失败回滚。
- 节点检测：无需导入客户端即可从节点卡片执行本机完整代理闭环，验证服务、配置、协议握手、认证和代理出站，并记录延迟与出口 IP；公网防火墙/NAT 可达性仍需异地验证。
- 实时观测：10 秒采样流量、CPU、内存、磁盘、负载、节点状态与进程 CPU/RSS；容量指标显示已用/总量。
- 流量时间轴：今日按小时、本账期按日展示下载/上传堆叠流量，支持提示卡与平均线。
- 多设备显示：流量脉络按 UDP 节点展示 Hysteria2、TUIC、Shadowsocks 最近完成窗口的客户端下行速率，并在窄屏自动折叠为 `+N`。
- 分享订阅：六种协议均可短时显示分享链接和二维码，并生成带流量响应头的 Clash/Mihomo 订阅。
- 东方科幻界面：桌面、平板和移动端响应式布局。

## 一键安装

支持 Debian、Ubuntu、Rocky Linux、AlmaLinux、Alpine；支持 `amd64`、`arm64`。

```bash
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh
```

同一个入口同时负责安装、更新和卸载：未安装时进入安装向导；检测到已有面板时默认提供安全更新，并可选择重新配置、保留数据卸载或彻底卸载。更新模式只替换校验后的二进制，不重新申请证书、不改 nginx 和节点配置；更新前会停服务复制 SQLite 一致性备份，健康检查失败则自动回滚。

首次安装可依次填写面板域名、HTTPS 端口、证书方式和 ACME 邮箱。填写域名后默认申请 Let’s Encrypt 证书，并可选择 HTTP-01 自动验证、仅 IPv4、仅 IPv6 或 Cloudflare DNS-01。纯脚本/CI 环境会自动保持非交互；也可显式使用 `--unattended`。

申请证书前应先把域名的 A/AAAA 记录指向该 VPS。HTTP-01 要求公网 TCP 80 可达；IPv4 NAT 端口受限但 IPv6 不限端口时，选择“仅 IPv6”，并确保域名 AAAA 记录正确。

NAT VPS、只开放指定端口的 VPS，需要在安装时把面板 HTTPS 端口设为可用的 **TCP** 端口。通过管道执行时，参数必须写在 `sh -s --` 后面：

```bash
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --port 你的可用TCP端口
```

如果提供商的公网端口与 VPS 内部端口不同，安装器的 `--port` 填内部监听端口，浏览器使用提供商分配的公网映射端口。IPv6 没有限制时，安装完成信息也会单独打印带方括号的 IPv6 访问地址。

常用安装参数：

```bash
# 直接更新到 latest（不修改现有配置、证书和节点）
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --update

# 更新到悟空验证过的 sing-box 稳定版本；旧二进制和配置快照会保留
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --update-sing-box

# 回退到上一次保留的 sing-box 版本
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --rollback-sing-box

# 完整备份后卸载 sing-box、节点 JSON 和对应服务定义；保留悟空面板
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --uninstall-sing-box

# 卸载面板并保留配置、数据库和 sing-box 节点
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --uninstall

# 完全删除悟空面板配置和数据；仍不删除 sing-box 节点
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --uninstall --purge

# 固定版本、自定义端口和入口
sudo sh install.sh --version v0.6.3 --port 9443 --base-path /my-secret-panel/

# 使用现有证书
sudo sh install.sh --domain panel.example.com \
  --cert-file /path/fullchain.cer --key-file /path/private.key

# HTTP-01（要求公网 80 未被占用）
sudo sh install.sh --domain panel.example.com --acme http --email admin@example.com

# IPv6 HTTP-01（适用于 IPv4 NAT 端口受限、IPv6 公网 80 可达）
sudo sh install.sh --domain panel.example.com --acme http \
  --acme-ip-version 6 --email admin@example.com

# Cloudflare DNS-01
sudo -E env CF_Token=... CF_Zone_ID=... sh install.sh \
  --domain panel.example.com --acme cloudflare
```

无域名时默认监听 HTTPS `9443` 并生成自签名证书。安装器不会修改 SSH、防火墙或云安全组，只会提示需要开放的端口。

### VLESS + WebSocket + Cloudflare Tunnel

这个节点类型需要 Cloudflare 账户和一个已接入 Cloudflare 的域名，但不要求用户把 Cloudflare API Key 交给面板。面板只接收单个 Tunnel 的运行 Token：

1. 在 Cloudflare Zero Trust 的 Networks → Tunnels 创建 remotely-managed Tunnel，选择 `cloudflared`，只复制运行命令中的 Token。
2. 普通单节点使用“部署节点”；多设备从右上角独立的“设备专用节点”入口进入。选择 VLESS + WebSocket + Cloudflare Tunnel 后填写公开主机名并粘贴 Token；本地 Origin 端口和 VLESS UUID 会自动生成，WebSocket 路径可留空随机生成。设备编队整组只需粘贴一次 Token。
3. 设备编队中的每台设备必须填写不同的 Cloudflare 公开主机名；WebSocket 路径可留空随机生成。
4. 部署完成后，从每张节点卡片复制 Path 正则和对应的 `http://127.0.0.1:<端口>`。
5. 回到同一个 Tunnel，为每台设备分别添加一条 Published application，填写对应的独立主机名和节点卡片所示 Path 正则；Service URL 使用对应节点卡片的本地地址。

客户端始终连接 Cloudflare 边缘的 `443/TLS`，sing-box Origin 只监听 VPS 的 `127.0.0.1`，不需要在防火墙或 NAT 上开放该端口。普通单节点各自管理 Tunnel；同一个设备组共享一个 Tunnel Token 和一个 `cloudflared` 连接器，并通过不同公开主机名的多条 Published application 路由到各自的本地 Origin。同一设备组不允许重复使用 Cloudflare 公开主机名。

如果已经测得更适合当前网络的 Cloudflare 优选域名或 IP，可在部署表单填写“优选连接域名 / IP”。面板只会把它写入分享链接和 Clash/Mihomo 订阅的 `server`；TLS `servername`、SNI、WebSocket `Host` 和 Tunnel Published application 路由仍使用上面的 Cloudflare 节点域名。该字段不能包含 `http://`、`https://`、路径或端口，留空即使用 Cloudflare 标准 Anycast。优选地址的可用性会随运营商、地区和时间变化，需要用户自行测试并维护。

首次部署时，面板会按固定 SHA-256 下载并安装官方 `cloudflared 2026.7.1`（`amd64`/`arm64`），为普通 Tunnel 节点或设备组创建 systemd/OpenRC 服务，并通过 `--token-file` 启动。现有 `cloudflared` 必须不低于 `2025.4.0`；自定义路径可使用 `--cloudflared` 或 `WUKONG_CLOUDFLARED_BIN`。普通 Tunnel 节点的生命周期会同时管理 sing-box 与 cloudflared；设备组中单个节点的停止、重启或删除只影响该节点，删除最后一台设备时才移除共享连接器。节点“检测”会从公网域名验证 Cloudflare TLS、WebSocket、VLESS 认证和代理出站完整链路。

### sing-box 安全更新与回退

悟空面板只允许安装内置清单中经过验证的 sing-box 版本，当前稳定版锁定为 `1.13.14`。全新 VPS 没有 `/etc/s-box/sing-box` 和旧 JSON 时，一键安装会下载官方资产、核对固定 SHA-256、验证包内版本并原子安装；检测到现有二进制则保持原版本不变。若只有旧 JSON 而缺少配套二进制，安装器会拒绝猜测版本，避免用新二进制误启旧配置。面板会按 1.10、1.11、1.12、1.13 的能力差异生成配置，并在升级前把旧 inbound、`block`/`dns` outbound、旧 TUN 地址、direct 目标覆盖和 `domain_strategy` 等字段迁移到 Rule Actions、Endpoint 与 `domain_resolver`。无法无损自动转换的 WireGuard outbound 会作为阻断项展示，不会猜测性重写。更新流程会：

1. 下载官方 GitHub Release 并核对固定 SHA-256。
2. 生成逐文件迁移预览，保留未知 JSON 字段，并拒绝存在阻断项的升级。
3. 检查配置引用的 `bind_interface` 是否存在，再用新二进制逐一检查迁移后的 JSON。
4. 保存旧二进制、版本号、校验和、服务文件、活动服务清单和全部 JSON 配置快照。
5. 仅停止当前正在运行且确实使用目标二进制的 sing-box 服务，并在停机窗口内安装配套二进制和配置。
6. 恢复服务后按各 inbound 的真实协议和凭据，通过本机入口访问多组双栈探测地址；配置、服务或协议探测任一失败都会恢复旧二进制和旧配置。

备份保存在 `/var/lib/wukong-panel/backups/sing-box/`。手动回退会恢复同一快照中的旧二进制和配套配置，而不是只替换二进制；刚才运行的新版本也会形成反向快照，因此可以再次切回。

`--uninstall-sing-box` 是独立的破坏性操作：先保存并校验 sing-box 二进制、全部 `/etc/s-box/*.json`、活动服务清单、受管 systemd/OpenRC 服务定义及启用状态，再停止服务并删除这些受管内容。证书等非 JSON 文件、悟空面板和 SQLite 数据库不会删除；删除阶段失败会自动恢复二进制、配置、服务定义和原活动服务。

## 架构与安全边界

```mermaid
flowchart LR
  B["浏览器 / HTTPS"] --> N["nginx 随机入口"]
  N --> W["wukong-web\n非特权用户"]
  W -->|"类型化请求 / Unix Socket"| A["wukong-agent\nroot"]
  A --> S["sing-box / systemd / OpenRC"]
  C["Cloudflare Edge :443"] --> F["cloudflared\n独立节点服务"]
  F -->|"127.0.0.1 Origin"| S
  A --> F
  W --> D[("SQLite WAL")]
  A --> D
  A --> K["root-only 机器密钥"]
```

- 管理账号默认为 `admin`；初始密码只在首次安装时打印，首次登录强制改密。
- 新密码使用 Argon2id（19 MiB、t=2、p=1），并兼容验证旧版 64 MiB 哈希；低内存主机会在认证后主动归还临时堆。节点密钥使用 AES-256-GCM，机器密钥权限为 `0600`。
- 首次登录强制改密完成前，后端拒绝面板数据接口，前端不会预加载总览、节点、任务、设置、端点或时间轴。
- 会话 Cookie 使用 `Secure`、`HttpOnly`、`SameSite=Strict`，所有变更 API 校验 CSRF。
- 登录按来源 IP 限速；所有节点变更、密钥显示与设置修改写入审计日志。
- Agent 不接收任意命令字符串，只执行固定类型操作。

## CLI

安装后 `wukongctl` 与 `wukong-panel` 指向同一二进制：

```bash
wukongctl doctor
wukongctl scan
wukongctl node create --name "AC-HY2" --server node.example.com --domain node.example.com \
  --mode prefer_v6 --ipv4-bind 192.0.2.10 --ipv6 2001:db8::10
wukongctl node create --protocol vless --name "AC-Reality" \
  --server node.example.com --domain www.cloudflare.com --mode prefer_v6
wukongctl node create --protocol vless-ws-tunnel --name "AC-CF-WS" \
  --server edge.example.com --ws-path /wukong-edge \
  --tunnel-token-file /root/cloudflare-tunnel.token --mode prefer_v6
wukongctl node create --protocol shadowsocks --name "AC-SS2022" \
  --server node.example.com --mode prefer_v6
wukongctl node create --protocol tuic --name "AC-TUIC" \
  --server node.example.com --domain node.example.com --mode prefer_v6
wukongctl node create --protocol trojan --name "AC-Trojan" \
  --server node.example.com --domain node.example.com --mode prefer_v6
wukongctl node action --id NODE_ID --action restart
wukongctl node action --id NODE_ID --action probe
wukong-panel singbox plan --target 1.13.14 --config-dir /etc/s-box
wukong-panel singbox migrate --target 1.13.14 \
  --config-dir /etc/s-box --output-dir /tmp/s-box-1.13
wukong-panel singbox check-interfaces --target 1.13.14 --config-dir /tmp/s-box-1.13
wukong-panel singbox probe --binary /etc/s-box/sing-box --config-dir /etc/s-box

# 从另一台主机按配置中的实际协议验证公网入口；纯 IPv6 节点可直接填写真实 IPv6
wukong-panel singbox probe --binary /path/to/sing-box --config-dir /path/to/probe-config \
  --server 2001:db8::10 --server-name node.example.com
```

`compat/deploy-hy2.sh` 保留原参数模式入口，并将参数交给 `wukongctl node create`。交互部署改由面板完成。

## API

管理 API 固定在 `/api/v1`：

- `auth/login|me|password|logout`
- `overview`、`metrics`、`metrics/endpoints`、`metrics/timeline`
- `nodes`、`nodes/batch`、`nodes/{id}/actions`、`nodes/{id}/share`
- `imports/scan|confirm`
- `system/sing-box/migration`
- `jobs`、`jobs/{id}/events`
- `settings`、`settings/subscription-token`

变更接口返回任务 ID；任务通过轮询或 SSE 获取进度。订阅接口位于 `/sub/{token}/clash.yaml`，订阅令牌与管理入口相互独立。

## 本地开发

```bash
cd web
npm install
npm run build
cd ..

go test ./...
go build -o build/wukong-panel ./cmd/wukong-panel

rm -rf /tmp/wukong-demo
./build/wukong-panel serve \
  --listen 127.0.0.1:8788 \
  --data-dir /tmp/wukong-demo \
  --config-dir /tmp/wukong-sbox \
  --base-path / --secure-cookie=false --demo
```

## 从现有服务器迁移

1. 安装面板但不要修改 sing-box 版本。
2. 在“接管节点”中查看扫描结果和共享服务关系。
3. 确认导入；导入过程不会重写现有 JSON。
4. 并行运行旧监控和悟空指标至少 24 小时。
5. 确认订阅、账期和流量一致后再停用旧 timer/service。

sing-box 1.10 配置仍以兼容模式接管；系统页可先只读预览迁移差异，一键脚本升级时再生成 1.13 配置并执行整体快照、协议探测和失败回退。迁移规则对应[官方迁移文档](https://sing-box.sagernet.org/migration/)。

## 卸载

```bash
sudo sh install.sh --uninstall          # 保留面板数据、节点和 sing-box
sudo sh install.sh --uninstall --purge  # 额外删除悟空面板自身数据
sudo sh install.sh --uninstall-sing-box # 备份后只卸载 sing-box 与节点服务
```

独立的 `uninstall.sh` 仍保留兼容。面板卸载和 purge 都不会删除 `/etc/s-box` 或任何节点服务；只有显式执行 `--uninstall-sing-box` 才会删除 sing-box 二进制、节点 JSON 和对应服务定义。

## License

MIT
