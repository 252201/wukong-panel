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

页面以“SSH 登录防护”说明用途，jail 名称放在技术详情中。未运行时不把无法获取的失败及封禁统计显示为 0；已有防护的启用或接管统一从参数表单预览，不创建重复防护。

默认 maxretry=5、findtime=600、bantime=3600、mode=normal。支持 normal/ddos/extra/aggressive，白名单支持 IPv4/IPv6/CIDR，保留回环，拒绝全地址白名单。白名单不会自动取浏览器、反代或中央主机的地址。

优先可读 systemd journal（需要 python3-systemd）；否则检查实际 auth.log、secure 或 messages，采用 polling 文件后端。使用发行版 `sshd` 过滤器，固定兼容 sshd-session 及 BusyBox syslog 前缀，通过独立 jail 参数覆盖，不修改默认过滤器。检测到真实失败日志时额外检查过滤器能否匹配；日志、依赖、过滤器或运行配置异常会明确提示。只防护实际 SSH TCP 端口。

未配置 SSH jail 时创建 `wukong-sshd`；已有正在运行的 SSH jail 先只读展示，预览接管后沿用原名称。单个默认 `sshd` 配置且服务明确停用时，在日志、过滤器、权限和后端校验通过后，可从页面“预览并启用现有防护”：沿用 `sshd` 名称，以独立覆盖应用所选参数，先备份、验证再启动服务并设置开机启动；失败恢复原配置及停用状态。存在其他启用配置、自定义名称、多个 SSH jail、服务状态不明或多个 firewalld 区域时仍需管理员核对，避免改变无关防护。Alpine 包可能默认启用 sshd 与 sshd-ddos，页面会如实提示。覆盖文件为 `/etc/fail2ban/jail.d/zzzz-wukong-ssh.local`，停用只关闭悟空管理的 jail，解除接管删除该覆盖并恢复原配置。

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

## UFW 旧端口规则

兼容 `ufw allow 20100` / `ufw deny 20100` 这种省略协议的单端口规则。它们作为一条 TCP/UDP 合并规则展示和接管，不拆成可独立删除的两条规则。识别前核对 `/etc/ufw/user.rules` 与 `user6.rules` 的完整 tuple 和 TCP/UDP 原生条目，显示实际 IPv4/IPv6 覆盖；缺失、重复或多出复杂匹配时仍只读，不假设旧规则均为双栈。接口、转发、应用名称及未完整识别的规则保持原有保护。

接管不改写原始防火墙文件。删除经过预览、备份及连接确认窗口，用原始合并语义同时移除 TCP 和 UDP，失败恢复原文件、所有权与内核规则。合并规则覆盖 SSH/面板端口时同样受保护；不允许把合并规则直接替换成单个协议，以免隐式删除另一协议。需要调整时先预览删除整条规则，再分别添加所需协议。新增规则仍只接受显式 TCP 或 UDP。
## 进程用途标注

系统页保留原始进程名，并在下方标注可识别的 Fail2ban 服务/客户端、firewalld 服务/客户端、UFW、nftables、iptables/ip6tables 规则工具，以及悟空安全恢复和规则加载进程。兼容 Python 解释器启动的服务与 Linux 截断的工具名；只按进程名及实际执行的脚本识别，不把参数中出现的工具名称当成服务。命令行只在主机本地用于识别，快照和数据库只保存固定用途标识。

用途标注随本机与舰队进程快照传递；旧 Agent 未上报用途时仍显示原始名称，已有节点名称保留。进程列表仍按资源使用排序和限量展示，标注不代表具体 SSH 防护已生效。UFW/nftables 通常没有常驻管理进程，真实防护状态以安全页为准。

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
WUKONG_SECURITY_BACKEND=ufw sh scripts/test-host-security-native.sh alpine:3.21
# ARM 主机可使用 WUKONG_SECURITY_ARCH=arm64
```

覆盖 TCP/UDP 真实收发和拒绝、ICMP/IPv6 控制通信、原生允许/拒绝与 IPv4/IPv6、第三方规则、持久化、真实 SSH 失败与成功、白名单、SSH 专用封禁、解封、重载后封禁、接管及解除接管、其他 jail 保留、Agent 被杀后的独立恢复和 PID 1 重启后的恢复。systemd 发行版同时验证 journal 和真实 sshd 文件日志，Alpine 验证文件日志。UFW 额外覆盖 IPv4/IPv6 同条件规则互换、CIDR/UDP 范围、替换中途失败，以及防火墙保持启用时完整等待 90 秒、由独立恢复服务还原实际连通性并保留 SSH 封禁。其他超时用例可缩短测试 journal 的期限，重启测试保留完整 90 秒窗口。第二个移除所有 capabilities 的容器验证不可用诊断。Debian 12 额外验证 Root Agent 的真实包安装保持保护停用；Debian 12/13、Ubuntu、Rocky、AlmaLinux、Alpine 纳入 PR CI。


## 清理并重新安装 Fail2ban

安全页的“修复与重新安装”提供独立预览。用于多个配置冲突或损坏的发行版软件包安装；不受普通 SSH 接管只读限制。预览显示目标主机、运行配置、清理目录及影响。应用必须使用相同 revision 并输入 `RESET FAIL2BAN`；旧远端 Agent 不具备 `security.fail2ban.reset` 能力时拒绝操作，轻量探针、离线及过期状态仍禁止写入。

- 先建立独立系统恢复任务，保存并校验备份。停止 Fail2ban 后重新核对配置，保存已完成数据库写入的整个 `/var/lib/fail2ban`，备份含文件内容、SHA-256、权限及空目录。备份以 root 权限保留在 Agent 的 `host-security/backup-<transaction>.json`。
- 清空固定的 `/etc/fail2ban`、`/var/lib/fail2ban`，使用发行版包管理器重新安装 Fail2ban 软件包；删除所有自定义 jail、白名单、过滤器、动作和历史封禁数据库，包含非 SSH 防护。Fail2ban 服务停止时解除它管理的当前封禁。主机防火墙的其他规则、SSH 服务、面板和节点不被重置；SSH 原始登录日志及 Fail2ban 诊断日志保留。
- 发行版默认文件恢复后，以独立 local 覆盖停用所有发行版 jail，验证配置并保持服务和开机启动停用。用户检查实际 SSH 端口、参数、日志及后端后，可从常规启用流程新建悟空防护。
- 安装或验证失败、Agent 崩溃或主机重启时，独立恢复任务恢复原配置、数据库、管理归属、服务及开机状态，重新同步原来的当前封禁。软件包升级不自动降级；恢复失败保留 pending journal 并重试，显示具体原因。
- 安装由后台任务执行，远端沿用串行命令与幂等回执，重装允许最长 9 分钟执行。请求不接受任意路径、软件包、shell 或动作。拒绝符号链接、特殊文件、子目录挂载、超过 64 MiB/4096 项的备份、自定义服务覆盖、外部数据库/运行路径、来源不明的软件包及缺少 `CAP_NET_ADMIN` 的容器。

本功能属于后续开发；未在生产 VPS 执行清理或重新安装。
