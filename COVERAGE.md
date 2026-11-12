# COVERAGE — 平台×模块×权限×来源台账

状态：NOT_TESTED / BUILT_NOT_RUN / PASSED / FAILED / DEFERRED / NOT_IMPLEMENTED
规则：未测格不写 PASSED；无基线不下完整性结论；每格有证据指针（TEST_RESULTS.md #编号）。

## v0.6 终态（2026-11-12，详见 TEST_RESULTS #39）

- 规则以**代码**为准（`rule_id =` / `finding_kv`）；文档可能滞后。v0.6 新增：WIN.EVT.SVC7045 / WIN.TRACE.PSHIST / WIN.FILES.ADS / LNX.PERSIST.SSHLOG / LNX.WEB.LOGATTACK / WIN.WEB.LOGATTACK / MID.MYSQL.SLOWLOG / MID.MYSQL.BINLOG；宝塔日志接入 LOGPOST 路径扩展。
- 原先标 DEFERRED 的 W10 WMI：代码已实现（WIN.BASE.WMICONSUMER 等），以代码为准。
- C 级仍 DEFERRED：深层 SAM/RID 劫持、内核 rootkit、内存取证、磁盘镜像模式、业务数据恢复、ROW binlog 完整还原。

## M0 兼容矩阵（2026-11-08）

| 平台格 | 优先 | 构建 | 启动 | 证据 |
|---|---|---|---|---|
| Win7 SP1 x64（VM .14） | P0 | PASSED | **PASSED**（CLI+GUI 自检） | #7 #10 |
| Win11 x64（开发机） | P0代表 | PASSED | PASSED | #7 |
| Win10 22H2 x64 | P0代表 | — | NOT_TESTED | |
| Server2008 R2 SP1 x64 | P0 | — | NOT_TESTED（无合法镜像） | |
| CentOS7 x86_64 用户态（centos7-full 容器） | P0 | PASSED | PASSED（静态二进制） | #11 |
| CentOS7 内核 3.10 真机 | P0 | — | NOT_TESTED（容器为 WSL2 内核） | #11 |
| Ubuntu 24.04（WSL） | P1 | PASSED | PASSED | #11 |
| Win7 SP1 x86 | P1(ADR-001) | DEFERRED | DEFERRED | 构建配置保留 |

## 模块覆盖（MVP 承诺，均 NOT_IMPLEMENTED 起步；M1 起逐项推进）

- Windows：W01 账户 / W02 登录隐藏 / W03 任务 / W04 服务 / W05 自启动(+次要持久化点) / W06 hosts / W07 进程连接(+挖矿) / W08 哈希签名(+粘滞键) / W09 事件日志(4624/4625 首规则) / W13 Web(A, v0.3)
- Linux：L01 UID0 / L02 SSH / L03 cron / L04 profile / L05 preload / L06 hosts / L07 systemd / L08 ELF包 / L09 进程(+挖矿) / L10 特权位 / L11 日志 / L13 痕迹(B, v0.3)
- C 级（DEFERRED）：W10 WMI / W11 深SAM / W12 策略 / L12 网络策略
