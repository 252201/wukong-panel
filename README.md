# 悟空面板

悟空面板是面向个人与小型团队的单机 VPS 节点控制台，将 Hysteria2 部署、生命周期管理、分享订阅、主机状态和整机流量账期放在同一个安全界面中。

![Version](https://img.shields.io/badge/version-v0.3.1-d4ad57)
![Go](https://img.shields.io/badge/Go-1.24+-52b690)
![Vue](https://img.shields.io/badge/Vue-3.5-52b690)

## 特性

- 单机自治：每台 VPS 独立安装，无需中心服务器。
- Hysteria2：IPv6 优先、纯 IPv4、纯 IPv6、NAT 本地绑定、设备专用节点。
- 安全管理：非特权 Web 服务与 root Agent 通过受限 Unix Socket 通信。
- 无损接管：扫描 `/etc/s-box` 与 systemd/OpenRC 服务，确认后导入，不重写未知字段。
- 安全变更：配置暂存、`sing-box check`、原子替换、SHA-256 快照与失败回滚。
- 实时观测：10 秒采样流量、CPU、内存、磁盘、负载、节点状态与进程 CPU/RSS；容量指标显示已用/总量。
- 流量时间轴：今日按小时、本账期按日展示下载/上传堆叠流量，支持提示卡与平均线。
- 多设备显示：流量脉络按节点展示 HY2 采集器最近完成窗口的客户端下行速率，并在窄屏自动折叠为 `+N`。
- 分享订阅：短时显示节点密钥，提供二维码及带流量响应头的 Clash/Mihomo 订阅。
- 东方科幻界面：桌面、平板和移动端响应式布局。

## 一键安装

支持 Debian、Ubuntu、Rocky Linux、AlmaLinux、Alpine；支持 `amd64`、`arm64`。

```bash
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh
```

在终端中执行上述命令会进入交互向导，可依次填写面板域名、HTTPS 端口、证书方式和 ACME 邮箱。填写域名后默认申请 Let’s Encrypt 证书，并可选择 HTTP-01 自动验证、仅 IPv4、仅 IPv6 或 Cloudflare DNS-01。纯脚本/CI 环境会自动保持非交互；也可显式使用 `--unattended`。

申请证书前应先把域名的 A/AAAA 记录指向该 VPS。HTTP-01 要求公网 TCP 80 可达；IPv4 NAT 端口受限但 IPv6 不限端口时，选择“仅 IPv6”，并确保域名 AAAA 记录正确。

NAT VPS、只开放指定端口的 VPS，需要在安装时把面板 HTTPS 端口设为可用的 **TCP** 端口。通过管道执行时，参数必须写在 `sh -s --` 后面：

```bash
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --port 你的可用TCP端口
```

如果提供商的公网端口与 VPS 内部端口不同，安装器的 `--port` 填内部监听端口，浏览器使用提供商分配的公网映射端口。IPv6 没有限制时，安装完成信息也会单独打印带方括号的 IPv6 访问地址。

常用安装参数：

```bash
# 固定版本、自定义端口和入口
sudo sh install.sh --version v0.3.1 --port 9443 --base-path /my-secret-panel/

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

## 架构与安全边界

```mermaid
flowchart LR
  B["浏览器 / HTTPS"] --> N["nginx 随机入口"]
  N --> W["wukong-web\n非特权用户"]
  W -->|"类型化请求 / Unix Socket"| A["wukong-agent\nroot"]
  A --> S["sing-box / systemd / OpenRC"]
  W --> D[("SQLite WAL")]
  A --> D
  A --> K["root-only 机器密钥"]
```

- 管理账号默认为 `admin`；初始密码只在首次安装时打印，首次登录强制改密。
- 密码使用 Argon2id，节点密钥使用 AES-256-GCM，机器密钥权限为 `0600`。
- 会话 Cookie 使用 `Secure`、`HttpOnly`、`SameSite=Strict`，所有变更 API 校验 CSRF。
- 登录按来源 IP 限速；所有节点变更、密钥显示与设置修改写入审计日志。
- Agent 不接收任意命令字符串，只执行固定类型操作。

## CLI

安装后 `wukongctl` 与 `wukong-panel` 指向同一二进制：

```bash
wukongctl doctor
wukongctl scan
wukongctl node create --name "AC-HY2" --domain node.example.com \
  --mode prefer_v6 --ipv4-bind 192.0.2.10 --ipv6 2001:db8::10
wukongctl node action --id NODE_ID --action restart
```

`compat/deploy-hy2.sh` 保留原参数模式入口，并将参数交给 `wukongctl node create`。交互部署改由面板完成。

## API

管理 API 固定在 `/api/v1`：

- `auth/login|me|password|logout`
- `overview`、`metrics`、`metrics/endpoints`、`metrics/timeline`
- `nodes`、`nodes/{id}/actions`、`nodes/{id}/share`
- `imports/scan|confirm`
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

sing-box 1.10 配置以兼容模式接管；新配置根据检测到的 sing-box 版本生成。跨版本升级前请阅读[官方迁移文档](https://sing-box.sagernet.org/migration/)。

## 卸载

```bash
sudo sh uninstall.sh          # 保留面板数据、节点和 sing-box
sudo sh uninstall.sh --purge  # 额外删除悟空面板自身数据
```

卸载器不会删除 `/etc/s-box` 或任何节点服务。

## License

MIT
