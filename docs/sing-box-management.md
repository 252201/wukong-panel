# sing-box 生命周期、迁移与配置管理

悟空面板深度集成了 sing-box 核心生命周期管理，提供无损平滑迁移、版本校验、快照备份与失败秒级回退保障。

---

## 内置版本管理策略

- **稳定版清单控制**：面板严格锁定经过全面兼容性验证的官方稳定版（如当前锁定 `1.14.x` 系列），从源头避免由于上游破坏性语法调整导致节点中断。
- **配置规则演进支持**：自动适配 1.10 至 1.14 的配置规范演进，平滑迁移 Rule Actions、Endpoints、现代 DNS 规范与分流策略。
- **未知字段完整保留**：自动扫描导入或迁移旧版本时，未知配置字段原样保留，绝不进行猜测性丢弃或重写。

---

## 升级与原子替换流程

通过面板前端或 CLI 执行 sing-box 更新时，遵循以下原子事务流程：

1. **资产校验**：下载官方稳定版 Release，校验针对架构的 SHA-256 哈希及二进制内部版本号。
2. **迁移预览与语法自检**：在新二进制下调用 `sing-box check` 预检全部生成的配置及网卡依赖，若存在阻断项立即终止升级。
3. **建立快照备份**：备份旧二进制、版本号、受管 systemd/OpenRC 服务文件及全部 JSON 配置快照至 `/var/lib/wukong-panel/backups/sing-box/`。
4. **停机切换与服务拉起**：仅在极短毫秒级停机窗口内替换二进制与配置，拉起活动服务。
5. **双栈闭环自检与自动回滚**：服务启动后，通过本机真实协议入口对节点执行握手自检；若配置、进程或连通性自检任一环节失败，**自动还原旧版本二进制与配置快照**，确保节点高可用。

---

## 常用维护命令

```bash
# 更新到面板验证过的 sing-box 稳定版
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --update-sing-box

# 手动回退到上一次备份的 sing-box 版本与配套配置
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --rollback-sing-box

# 仅卸载 sing-box、节点 JSON 及服务（保留悟空面板及数据库）
curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh \
  | sudo sh -s -- --uninstall-sing-box
```
