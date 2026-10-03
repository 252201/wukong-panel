# 防火墙与 Fail2ban SSH 管理

安全页随 v1.7.0 发布。本功能从 v1.6.6 开发，并保留非特权 ICMP Echo 兼容。所有系统命令在 Root Agent 执行，Web 经登录、CSRF、审计与任务日志调用 Unix Socket；完整远端面板沿用 HTTPS 舰队命令、串行执行和幂等回执。发布本身不会修改 VPS。

## 使用

1. 打开侧栏“安全”，选择本机或在线完整远端面板。切换主机会销毁表单和预览，确认只绑定原目标主机。旧 Agent、轻量探针和离线主机不可操作；超过 90 秒的采样显示过期。
2. 查看后端、入站策略、规则归属及检测到的实际管理端口。多个后端、无法识别的外部入站链、复杂规则或缺少 CAP_NET_ADMIN 时只读。云安全组与 NAT 映射单独配置。
3. 安装缺少的组件。安装为异步任务；安装本身不启动入站保护。包管理失败显示任务原因，临时 apt 启动限制文件会恢复。
4. 预览首次开启：拒绝其他入站、允许出站，保留原规则，放行 SSH、真实公共 Nginx 入口、80/443 与当前公网节点端口。无法检测时填写真实 SSH/面板端口；没有默认 22/8788。回环监听和 Cloudflare Tunnel 源站不进入公网放行清单。后续节点不会自动开放端口。
5. 应用可能影响连接的防火墙变更后，通过新的 SSH/面板连接检查，再在 90 秒内确认。超过窗口或主机重启，独立恢复服务回滚。恢复服务无法建立、备份无法验证、外部状态发生变化时拒绝应用。
6. 添加允许/拒绝 TCP/UDP 单端口或范围，来源可为任意、IPv4/IPv6 或 CIDR。简单外部规则需预览接管才可删除；管理入口规则受到保护。复杂链、NAT、转发规则保持只读，页面没有重置整机规则的操作。

firewalld 保留区域绑定、已有永久配置和运行规则。停用状态先读取离线配置并预先写入管理放行端口，再启动服务。默认拒绝区域明确保留 ICMP/IPv6 控制通信；首次开启超时会恢复原停用状态。多个绑定区域无法确认 SSH 所属区域时保持只读，需在主机核对。nftables 仅原子替换 `inet wukong_panel`，使用独立 `wukong-firewall` 启动加载器；不修改或调用发行版的全局 nftables 重载文件。停用会撤销悟空的拒绝入站及 deny 执行，保留可再次启用的规则配置。

UFW 对相同协议、端口范围、来源的允许/拒绝采用替换：预览同时列出删除旧规则与添加新规则，两种方向都要求连接确认。仅可替换已由悟空管理且未受保护的简单规则；外部规则需先确认接管。拒绝规则使用 `prepend`，按 IPv4/IPv6 各自的规则顺序置于已有允许规则之前，避免混用双栈编号。规则顺序遵循 [UFW 官方发行版手册](https://manpages.debian.org/trixie/ufw/ufw.8.en.html)。

## SSH 防护

默认 maxretry=5、findtime=600、bantime=3600、mode=normal。支持 normal/ddos/extra/aggressive，白名单支持 IPv4/IPv6/CIDR，保留回环，拒绝全地址白名单。白名单不会自动取浏览器、反代或中央主机的地址。

优先可读 systemd journal（需要 python3-systemd）；否则检查实际 auth.log、secure 或 messages，采用 polling 文件后端。使用发行版 `sshd` 过滤器，固定兼容 sshd-session 及 BusyBox syslog 前缀，通过独立 jail 参数覆盖，不修改默认过滤器。检测到真实失败日志时额外检查过滤器能否匹配；日志、依赖、过滤器或运行配置异常会明确提示。只防护实际 SSH TCP 端口。

未配置 SSH jail 时创建 `wukong-sshd`；已有正在运行的 SSH jail 先只读展示，预览接管后沿用原名称。已配置但停用、多个 SSH jail 或多个 firewalld 区域需在主机核对，避免重复防护。Alpine 包可能默认启用 sshd 与 sshd-ddos，页面会如实提示。覆盖文件为 `/etc/fail2ban/jail.d/zzzz-wukong-ssh.local`，停用只关闭悟空管理的 jail，解除接管删除该覆盖并恢复原配置。

UFW 使用发行版 `iptables-multiport`（官方 UFW action 默认会封锁所有端口）；firewalld 使用 `firewallcmd-rich-rules` 和实际单个 SSH 区域，多个 SSH 端口分别建立 action；nftables 使用 `nftables-multiport`。状态校验实际动作、过滤表达式、日志源、白名单及内核中的封禁规则。关闭会使 SSH 封禁失效的防火墙时，要求先停用相关防护。

防火墙重载及配置恢复后保留各 jail 已有封禁；原生规则仍在时保持 jail 运行。丢失的封禁通过解封/再封禁恢复，不修改其他 jail 的配置；这会重新开始该 IP 的封禁时长。未知外部封禁动作无法验证时变更会失败并进入恢复流程，需在主机核对。

配置行为参考 [官方 jail.conf](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf)、[firewalld rich-rules action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/firewallcmd-rich-rules.conf)。

## API

所有写接口使用现有登录鉴权与 `X-CSRF-Token`。本机接口：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/v1/system/firewall?zone=public` | 实时防火墙状态 |
| GET | `/api/v1/system/fail2ban` | 实时 SSH 防护状态 |
| POST | `/api/v1/system/{firewall,fail2ban}/preview` | 参数校验、差异、状态 revision |
| POST | `/api/v1/system/{firewall,fail2ban}/apply` | 带 revision 应用已预览请求 |
| GET | `/api/v1/system/security-transactions/{id}` | 确认或恢复结果 |
| POST | `/api/v1/system/security-transactions/{id}/confirm` | 确认本次连接安全 |

防火墙 operation：install、enable、disable、add、delete、adopt；SSH operation：install、enable、configure、adopt、disable、detach、reload、unban。只接受类型化规则、配置、已识别 jail、单个 IP 与事务 ID，不接受 shell、配置路径或动作模板。安装返回 `jobId`；其他应用返回真实状态与 transaction。

远端将上述 `/system/...` 放在 `/api/v1/fleet/hosts/{hostId}/system/...` 下，要求 `security.firewall` 或 `security.fail2ban` 能力。在线读取也使用实时命令；离线仅展示最后快照和采样时间。安全能力与原 Fleet 协议兼容，缺少能力不排队发送命令。

## 恢复与诊断

状态、校验后的配置备份及 pending journal 位于 `WUKONG_SECRET_DIR/host-security`，仅 root 可访问。永久独立 `wukong-security-recovery` systemd/OpenRC 服务每秒检查 journal，不依赖 Web/Agent 存活；检测 boot ID/PID 1 变化会立即恢复未确认事务。失败保留 journal 并重试，界面显示具体恢复错误。勿手工删除尚未完成的 pending/backup 文件。

恢复只操作备份中的固定路径、选定 firewalld 区域、悟空 nftables 表和识别的 jail。云侧断网或 NAT 映射不由此恢复任务管理。

UFW 原先已启用时，恢复磁盘配置后必须再执行 `reload` 才完成内核恢复，不能只调用 `enable`。这也适用于 v1.7.0 写出的旧事务；重载失败会保留 pending journal，恢复服务继续重试，并在完成重载和封禁同步后才记录已回滚。原先未启用时仍恢复为停用状态。

## 验证

`go test ./...`、`go test -race ./...`、`go vet ./...`；`cd web && npm test && npm run build`；Linux amd64/arm64 编译。双实例舰队测试实际通过 HTTPS、CSRF、任务、回执与持久化 journal，原生命令使用隔离 fixture，验证所选目标和并发重复写只执行一次。

真实 Linux 集成测试运行在无公网映射的可删除特权容器，使用 veth/network namespace 与实际 SSH 46961 和 Nginx 9443。不会修改 Docker 宿主防火墙或线上主机：

```sh
sh scripts/test-host-security-native.sh debian:12
sh scripts/test-host-security-native.sh debian:13
sh scripts/test-host-security-native.sh ubuntu:24.04
sh scripts/test-host-security-native.sh rockylinux:9
sh scripts/test-host-security-native.sh almalinux:9
sh scripts/test-host-security-native.sh alpine:3.21
# ARM 主机可使用 WUKONG_SECURITY_ARCH=arm64
```

覆盖 TCP/UDP 真实收发和拒绝、ICMP/IPv6 控制通信、原生允许/拒绝与 IPv4/IPv6、第三方规则、持久化、真实 SSH 失败与成功、白名单、SSH 专用封禁、解封、重载后封禁、接管及解除接管、其他 jail 保留、Agent 被杀后的独立恢复和 PID 1 重启后的恢复。systemd 发行版同时验证 journal 和真实 sshd 文件日志，Alpine 验证文件日志。UFW 额外覆盖 IPv4/IPv6 同条件规则互换、CIDR/UDP 范围、替换中途失败，以及防火墙保持启用时完整等待 90 秒、由独立恢复服务还原实际连通性并保留 SSH 封禁。其他超时用例可缩短测试 journal 的期限，重启测试保留完整 90 秒窗口。第二个移除所有 capabilities 的容器验证不可用诊断。Debian 12 额外验证 Root Agent 的真实包安装保持保护停用；Debian 12/13、Ubuntu、Rocky、AlmaLinux、Alpine 纳入 PR CI。
