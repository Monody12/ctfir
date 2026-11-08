# COVERAGE — 平台×模块×权限×来源台账

状态：NOT_TESTED / BUILT_NOT_RUN / PASSED / FAILED / DEFERRED / NOT_IMPLEMENTED
规则：未测格不写 PASSED；无基线不下完整性结论；每格有证据指针（TEST_RESULTS.md #编号）。

## M0—M8 终态矩阵（2026-11-09，详见 TEST_RESULTS #10-#20）

- **模块实现：Windows 10/10（A6+B4 含 W13）；Linux 12/12（A7+B5 含 L13）；规则 35 条全部有样本**
- 非功能：JSONL 事件流 / 取消保 partial / 超时预算 / 原子写 / integrity.sha256 / explain+report 离线链 / GUI 复制建议
- C 级 DEFERRED：W10 WMI、W11 深SAM、W12 策略、L12 网络策略（发布说明如实标注）

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
