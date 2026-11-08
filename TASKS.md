# TASKS

状态枚举：TODO / IN_PROGRESS / BLOCKED / IMPLEMENTED_NOT_TESTED / PASSED / FAILED / DEFERRED
来源：PLAN.md §13（T25 为 v0.3 新增）。验收定义见 PLAN 对应行。

| ID | 任务 | 依赖 | 状态 | 证据 |
|---|---|---|---|---|
| T01 | 资源/授权/范围台账 | — | PASSED | AGENTS.md 环境事实；PLAN §12.1 v0.3 实测块 |
| T02 | AGENTS 与状态文件八件套 | T01 | PASSED | 本目录文件清单 |
| T03 | 许可与依赖锁（nlohmann/json） | T01 | TODO | M1 第一步 |
| T04 | Win32 /MT PoC（x64） | — | **PASSED** | TEST_RESULTS #7 #10（Win7 真机）；x86 按 ADR-001 DEFERRED |
| T05 | musl C++ PoC（Alpine 静态） | — | **PASSED** | TEST_RESULTS #11（内核 3.10 真机格 NOT_TESTED） |
| T06 | schema 与模型 | T02 | TODO | M1 |
| T07 | scheduler 与取消 | T06 | TODO | M1 |
| T08 | 安全文件读取/证据 | T06 | TODO | M1 |
| T09 | Linux UID0 纵向闭环 | T05-T08 | TODO | M1 |
| T10 | Windows 任务纵向闭环 | T04,T06-T08 | TODO | M1 |
| T11 | 报告与转义 | T06,T09,T10 | TODO | |
| T12 | Linux SSH/cron | T09 | TODO | |
| T13 | Linux profile/preload/hosts | T09 | TODO | |
| T14 | Windows 账户/组/界面隐藏 | T10 | TODO | |
| T15 | Windows 服务/启动/hosts | T10 | TODO | |
| T16 | B类文件/包/进程基础 | T12-T15 | TODO | |
| T17 | GUI 最小完整交互 | T07,T10,T11 | TODO | |
| T18 | CLI/help/doctor | T07,T11 | TODO | |
| T19 | 普通/高权限回归 | T12-T18 | TODO | |
| T20 | 模糊/故障/隐私测试 | T08-T18 | TODO | |
| T21 | 全净断网兼容 | T04,T05,T19,T20 | TODO | |
| T22 | RDP/scp 手册与搬运测试 | T21 | TODO | |
| T23 | 平台 ZIP 及发布清单 | T03,T21,T22 | TODO | |
| T24 | 用户 5 分钟验收及反馈回归 | T23 | TODO | |
| T25 | Web 模块 W13 三条起步规则 | T12-T15 | TODO | v0.3 新增（A级） |

## 夹具登记（Win7 VM，全部 `ctfir-marker` 前缀，测后清理）

| 日期 | 对象 | 用途 | 清理状态 |
|---|---|---|---|
| 2026-11-09 | ctfir-marker-task（计划任务） | W03 正例 | 已删除 |
| 2026-11-09 | ctfir-marker（用户+Administrators） | W01 正例 | 已删除 |
| 2026-11-09 | ctfir-marker-svc（服务 binPath→Temp） | W04 正例 | 已删除 |
| 2026-11-09 | UserList\ctfir-marker (DWORD) | W02 正例 | 已删除 |
| 2026-11-09 | HKLM Run\ctfir-marker | W05 正例 | 已删除 |
| 2026-11-09 | hosts: 10.66.0.66 ctfir-marker.local | W06 正例 | hosts.bak 恢复 |
| 2026-11-09 | ctfir-gui-show 交互任务(WP5验收) | GUI 显示 | 已删除 |
| 2026-11-09 | RDP 临时开启(fDenyTSConnections+防火墙) | 视觉验收通道 | 已回滚(=1+规则禁用) |

备注：M0 在 Win7 VM 仅建立 `C:\ctfir-test\` 部署目录并运行只读 PoC（未建夹具）。
