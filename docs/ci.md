# 按改动范围运行 PR CI

CI 比较 PR merge-base 与 head 的完整 Git 文件列表，不通过 GitHub 文件列表 API，不受 300 文件截断影响。删除和重命名前后的路径均参与判断；无法读取提交、版本不一致或分流脚本测试失败时，最终 `test` 检查失败。

| 改动范围 | 检查 |
|---|---|
| `web/`、`internal/web/dist/` | 前端测试、类型检查、生产构建 |
| 普通采样、探针、网络检测、地区识别、协议配置 | Go race/vet、现有 ICMP/舰队/协议集成检查、Linux 双架构编译 |
| 主机安全、Agent、认证、共享 model/config/store、Web 后端、面板命令入口 | 上述 Go 检查及 7 组原生安全矩阵 |
| 安装/卸载/引导脚本、兼容安装器及安装测试脚本 | 现有安装器脚本回归及 5 个发行版安装器检查 |
| 主机安全测试脚本、`scripts/security/` | Go 检查及原生安全矩阵 |
| `go.mod`/`go.sum`、非版本 Makefile 修改、workflow、分流脚本、发布构建脚本、未识别的新输入 | 完整检查 |
| 文档、宣传图片 | 轻量分流和版本一致性检查 |

组合改动取检查范围的并集。纯版本更新仅忽略 Makefile 的字面 `VERSION ?=` 值、package.json 顶层 version，以及 package-lock.json 顶层和根包 version；依赖、脚本、其他构建字段和依赖包版本变化不能借此跳过检查。每个 PR 都核对 Makefile、package.json、lockfile 根版本，以及 README 的版本徽标和安装示例一致。

## 必需检查与跳过行为

保留分支保护要求的 `test` 和 5 个 `installer-matrix (...)` 名称，无需调整分支保护。

- `test` 是汇总检查，等待所有相关任务。需要执行的任务必须成功；失败、取消、缺失输出和意外跳过都会阻止合并。
- 与安装器无关时，5 个兼容检查只运行快速说明步骤，不 checkout、不下载镜像、不启动发行版容器，仍提供现有必需状态。
- 前端、后端、安装回归和原生安全任务按范围合法跳过。workflow 不使用顶层 paths 过滤，避免必需检查永远 pending。
- 修改 workflow 或分流代码本身时运行完整检查，验证分流机制及原有测试拆分。PR 更新继续通过 concurrency 取消过时 run。

本配置只调整 PR CI。正式 Release 的构建、版本/源码/架构校验、发布资产验收仍由 Release workflow 执行；本次没有修改发布 workflow、发布版本或线上主机。

本地验证分流规则：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p ci_scope_test.py -v
python3 scripts/ci_scope.py --base <完整-base-SHA> --head <完整-head-SHA>
```

测试覆盖 UI 快速路径、纯版本、共享安全依赖、未知输入、删除/重命名、超过 300 个文件、特殊文件名、merge-base 和失败/取消处理。新增公共模块或调整依赖边界时应同时维护分流规则与相应测试；无法限定影响时保留完整检查。
