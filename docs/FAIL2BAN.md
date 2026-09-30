# Fail2ban SSH 防护

系统页提供 Fail2ban 服务状态、悟空 SSH 防护启用/关闭、触发次数、观察窗口、封禁时长、检测模式、可信 IP/CIDR、封禁列表与逐条解封。完整远端 Agent 支持相同操作，轻量探针只读且不能执行这些命令。离线远端仅展示最后快照；旧 Agent 需升级后才能使用。

## 首次启用

1. 在目标 VPS 安装并启动 Fail2ban。面板检测到缺少依赖或服务未运行时会显示说明；Debian/Ubuntu、Alpine 提供可复制的安装/启动命令，其他发行版使用自己的软件包管理器。安装和启动需要在该 VPS 的 SSH 终端执行，启动服务会加载已有启用规则。
2. 返回系统页刷新，核对实际 SSH 监听端口、日志来源。
3. 填写自己的管理出口 IP 或可信 CIDR，支持 IPv4、IPv6，每行一条。不要填写服务器 IP 来替代客户端出口 IP；出口变化时同步更新。主机本身和回环地址另由 Fail2ban 自动忽略。
4. 勾选“启用悟空 SSH 防护”并保存。默认 10 分钟内失败 5 次，封禁 1 小时。先使用标准模式，按需要切换严格模式。

标准模式使用发行版的 `sshd[mode=normal]` 过滤器。严格模式使用 `aggressive`，增加异常握手和部分探测匹配，可能误封反复中断握手的合法客户端。一次性扫描不一定达到阈值。实际匹配能力依赖主机所安装的 Fail2ban 版本及 SSH 过滤器。

## 配置与隔离

- 面板只管理 `wukong-sshd`，配置为 `/etc/fail2ban/jail.d/wukong-sshd.local`；其他运行规则只展示名字。不会修改现有 `sshd` 等规则，因此它们也可能独立封禁相同 IP。
- 只 reload/stop 悟空规则，不全局重启或停止 Fail2ban。关闭悟空规则会解除其当前封禁；解封也只针对悟空规则，其他规则的封禁需单独处理。白名单变更不会代替对已有封禁的手动解封。
- 自动读取运行中 `sshd` 的监听端口，不假设为 22。依赖 `ss` 可读取进程信息，Root Agent 以 root 运行；SSH 改端口后重新保存防护配置以更新保护端口。
- systemd 主机使用日志 journal，并匹配 `sshd`、`sshd-session`、`sshd-auth` 来源，避免只读空的 `/var/log/auth.log`。需要 Fail2ban 的 systemd Python 后端依赖。其他主机检测 `/var/log/auth.log`、`/var/log/secure` 中有效的 SSH 日志；未启用认证日志的 Alpine 需先配置 syslog 写入认证日志，面板会拒绝在没有有效日志时启用。
- 封禁 action 使用目标主机 Fail2ban 的发行版/管理员默认设置，不自行安装或切换 UFW、firewalld、nftables。主机的 action 与 IPv4/IPv6 防火墙能力需要匹配；云厂商安全组和上游 DDoS 防护另行配置。
- 保存前验证输入；原子写入配置后运行 `fail2ban-client -t`，仅重载本规则，再校验运行参数及白名单。失败恢复旧配置和规则状态，Root Agent 启动时恢复中断的事务。面板配置被外部修改、同名规则并非由面板创建或运行参数/白名单不一致时转只读，需在服务器核对。事务元数据保存于 root 专属 SecretDir 的 `fail2ban` 子目录。
- HTTP 写操作要求有效管理员登录和 CSRF；Root Agent 接口要求 Agent token；远端通过已有加密命令通道操作，并保留操作审计。白名单不会自动从浏览器 IP 推断，避免反代/CDN/VPS 出口混淆。

Fail2ban 是重复失败来源的事后封禁。公钥认证、关闭密码登录、来源限制和恢复入口仍需单独设置。

## 验证

常规 `go test ./...` 覆盖参数校验、独立规则启停/解封、配置失败回滚、启动恢复、外部修改保护、权限/CSRF、远端兼容与离线限制，以及双实例中央→远端操作隔离。

可选真实客户端测试使用官方 Fail2ban 源码 checkout：

```sh
F2B_SOURCE_DIR=/absolute/path/to/fail2ban go test ./internal/fail2ban -run TestRealClientIsolatedLifecycle -v
```

测试使用独立临时配置、日志、socket、PID 和不修改防火墙的 dummy action，验证真实客户端启用、保留封禁的重载、解封、SSH 日志触发自动封禁、白名单排除、停用及其他 jail 隔离。常规测试未设置该变量时跳过此项。本地已对官方 1.1.0 客户端完成该验证。另在隔离 Debian 12 arm64 Linux 网络命名空间中，在真实 nftables 内核上验证了悟空防火墙模块新增、持久化和删除端口规则，并用官方 Fail2ban 1.1.0 的 nftables action 验证日志自动封禁、客户端封禁/解封及停机清理。此验证覆盖上述隔离环境和 action；其他发行版、内核或管理员自定义 action 仍需按目标环境复核。

参考：[Fail2ban 官方配置](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf)、[客户端命令](https://github.com/fail2ban/fail2ban/blob/master/man/fail2ban-client.1)、[SSH 过滤器](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/sshd.conf)。
