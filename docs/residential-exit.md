# 双 VPS 落地 IP 出口配置指南

系统页的“落地 IP 出口”用于将 A 机（入口机）上的指定代理节点流量，通过系统级 WireGuard 隧道转发至 B 机（出口机）并以 B 机的 IPv4 进行 NAT 落地出口。

---

## 核心设计与安全约束

1. **凭据安全**：面板不需要接收 B 机的 SSH 密码、SSH 私钥或 WireGuard 私钥。
2. **Fail-Closed 路由保护**：
   - A 机配置使用专属 fwmark `102` 与路由表 `166`。
   - 守护服务始终先写入 IPv4/IPv6 `unreachable default` 路由，仅当 WireGuard 握手成功且在线时才以更低 metric 的隧道路由覆盖 IPv4。
   - 当隧道停止、握手超时或 B 机断线时，落地节点连接直接安全阻断（fail-closed），**绝不会**回退并泄漏到 A 机的公网真实出口。
3. **纯 IPv4 落地**：落地出口节点强制为纯 IPv4 模式，自动取消本机动态地址跟随。

---

## 配置步骤

### 1. 在 A 机生成接入脚本
1. 在 A 机悟空面板进入 **系统 → 落地 IP 出口**。
2. 填写 A 机的公网 IP 或域名，以及预分配的 WireGuard UDP 监听端口（暂时留空 B 机公钥）。
3. 保存后，面板将生成一行专用于 B 机的安装命令。

### 2. 在 B 机执行安装
复制该命令在目标 B 机以 root 运行。安装器将：
- 自动安装依赖并生成 B 机本地私钥；
- 开启系统 IPv4 内核转发并配置 iptables/nftables MASQUERADE NAT 规则；
- 命令行输出可安全公开的 `B_PUBLIC_KEY`。

### 3. 将公钥填回 A 机
将 `B_PUBLIC_KEY` 复制并粘贴回 A 机面板的对应表单中保存。A 机 Agent 写入 root-only WireGuard 配置并启动系统服务。

### 4. 绑定节点出口
在“节点管理”中创建或编辑节点，将“出口位置”由“本机直出”切换为“B 机落地 IP”。

---

## 移除与清理

如需停用落地出口：
1. 先在 A 机面板将所有相关节点的出口切回“本机直出”，并从系统页删除落地出口配置。
2. 在 B 机执行清理命令：
   ```bash
   curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
     | sudo sh -s -- --remove-residential-peer
   ```
   清理脚本仅精准移除带有悟空签名规则的虚拟接口，保留系统的 `wireguard-tools`、`iproute2` 及全局转发状态。
