# TASKS

状态枚举：TODO / IN_PROGRESS / BLOCKED / IMPLEMENTED_NOT_TESTED / PASSED / FAILED / DEFERRED
来源：PLAN.md §13（T25 为 v0.3 新增）。验收定义见 PLAN 对应行。

**v0.8.0（2026-11-13）**：Windows Server / AD 文件与注册表模拟。见 TEST_RESULTS #43、ADR-011。GUI 无写动作。JW2026-WIN7-01 **待练题，勿清**。

| ID | 任务 | 依赖 | 状态 | 证据 |
|---|---|---|---|---|
| T28 | Server/AD 考点覆盖（GPP/NTDS/SYSVOL/凭据防护 + hive/lsass） | T27 | **PASSED** | TEST_RESULTS #43：Win 96/96、Linux 92/92；Win7 42/42 HIT；VERIFY-GONE PASS；cleanup 恢复 |

**v0.7.0（2026-11-12）**：处置工作台（个人防护 / 团队综合 / 全部）。见 TEST_RESULTS #41。GUI 无写动作。JW2026-WIN7-01 **待练题，勿清**。

| ID | 任务 | 依赖 | 状态 | 证据 |
|---|---|---|---|---|
| T26 | 处置工作台（triage + display_action + HTML + GUI + CLI 清单） | T17,T18 | **PASSED** | TEST_RESULTS #41：单测 66/0；Win7 立刻清 25 / 再加固 13 / 溯源 17 / Web 0 / 清单 18 / 合计 73；W1–W13 默认队列均有已填命令 |
| T27 | CI 修复 + 宿主兼容警告 + `ctfir actions` + Linux 0.7.0 回归 | T26 | **PASSED** | TEST_RESULTS #42；ADR-010 |

**v0.6（2026-11-12）**：R16 五点 + Web GET 日志攻击 + MySQL slow/binlog 已实现并回归，见 TEST_RESULTS #39。历史 T03–T25 表未逐行回写（早期里程碑已在 STATUS/TEST_RESULTS 闭合）。

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
| 2026-11-09 | centos-ir-lab 容器内 ctfir-marker 全套(UID0/cron/hosts/webshell/shadow/caps/timer/at/基线) | LNX 新规则正例 | 已清理复验(15/15) |
| 2026-11-09 | A7C9 夹具(外部AI部署, 仅只读断言未动) | 八项对接 | 保留待用户 Cleanup 决定 |
| 2026-11-12 | JW2026-WIN7-01 练习套（用户 ctfir-marker$、Guest→Admins、Run/任务/服务/IFEO/登录脚本、hosts 10.66.0.88、portproxy 13389、Temp/桌面文件+ADS、共享、EnableLUA=0、LimitBlankPasswordUse=0） | 经纬杯安全防护赛 Win7 主机题 | **待练题，勿清**；还原用 `C:\ctfir-test\jw2026_win7_01_cleanup.cmd` |
| 2026-11-13 | AD-SERVER-01（SYSVOL GPP/GptTmpl、ntds 副本/IFM、sam.save、lsass.dmp、DSRM/LDAP/WDigest 等注册表） | v0.8 Server/AD analog | **已清理**；JW2026 未动；Spooler 仍 RUNNING；Netlogon DisablePasswordChange=1 / SealSecureChannel=0 为实验室原值 |

备注：M0 在 Win7 VM 仅建立 `C:\ctfir-test\` 部署目录并运行只读 PoC（未建夹具）。
