# COVERAGE — 平台×模块×权限×来源台账

状态：NOT_TESTED / BUILT_NOT_RUN / PASSED / FAILED / DEFERRED / NOT_IMPLEMENTED / AUTOMATED_SUBSTITUTE
规则：未测格不写 PASSED；无基线不下完整性结论；每格有证据指针（TEST_RESULTS.md #编号）。无法提供真实 OS/内核时用 AUTOMATED_SUBSTITUTE（写清技术原因与替代），不再空标 manual。

## v0.6.1 终态（2026-11-12，详见 TEST_RESULTS #40）

- 规则以**代码**为准（`rule_id =` / `finding_kv`）。检测点仍 **142**。v0.6.1 无新规则 ID；Windows 新增 `mod_mysql_win`，与 Linux 共用 MID.MYSQL.LOGSHELL / SLOWLOG / BINLOG；事件 XML 解析支持 2008 R2 `Qualifiers` 形态；BootExecute 正确解码 REG_MULTI_SZ。
- 原 cases TSV 中全部 `manual` 行已改为 `auto`，纳入 `fixture_win.py` / `fixture_linux.sh` / `fixture_builder_centos.sh` / `fixture_hidepid.sh` / `fixture_distros.sh` / `test_evt_xml.cpp`。
- 原先标 DEFERRED 的 W10 WMI：代码已实现（WIN.BASE.WMICONSUMER 等），以代码为准。
- C 级仍 DEFERRED（**未实现范围**，不是未写测试）：深层 SAM/RID 劫持、内核 rootkit、内存取证、磁盘镜像模式、业务数据恢复、ROW binlog 完整还原。

## 兼容矩阵（2026-11-12 更新）

| 平台格 | 优先 | 构建 | 运行/夹具 | 证据 |
|---|---|---|---|---|
| Win7 SP1 x64（VM .14） | P0 | PASSED | **PASSED**（CLI+GUI 自检 + 历史真机夹具） | #7 #10 #17 |
| Win11 x64（开发机 10.0.26100） | P0代表 | PASSED | **PASSED** fixture_win **29/29**；单测 **59/59** | #40 |
| Win10 22H2 x64 | P0代表 | — | 本机不是 22H2，无该版映像，**不标 PASSED** | #40 |
| Server 2008 R2 SP1 x64 真 OS | P0 | — | **AUTOMATED_SUBSTITUTE**：Win11 无法跑 2008 R2 Windows 容器（容器需匹配宿主内核，且镜像极重/无合法来源）。替代 = `test_evt_xml` 5/5（含 `<EventID Qualifiers="16384">7045</EventID>` 与 4697）+ 本机 `_WIN32_WINNT=0x0601` API 由 fixture_win 行使。不宣称 2008 R2 OS 已测。 | #40 |
| CentOS 7 x86_64 用户态（centos:7 / centos-ir-lab） | P0 | PASSED（musl 静态） | **PASSED**：centos:7 fixture_linux **42/42**；centos-ir-lab **75/75** | #11 #40 |
| CentOS 7 内核 3.10 真机 | P0 | — | **AUTOMATED_SUBSTITUTE**：Docker 共享宿主内核（本机 WSL2 `6.6.87.2-microsoft-standard-WSL2`），无法启动 3.10。替代 = 3.10 时代用户态（centos:7 glibc 2.17）全套夹具。未起 QEMU 3.10 VM。不宣称 3.10 内核已测。 | #40 |
| Alpine 3.20（构建与夹具） | P1 | PASSED | **PASSED** fixture **42/42**；hidepid L39 PASS；单测 **55/55** | #40 |
| debian:8 / ubuntu:16.04 用户态 | P1 | 同 musl 二进制 | **PASSED** 各 **42/42** | #40 |
| Ubuntu 24.04（WSL） | P1 | PASSED | PASSED（历史自检） | #11 |
| Win7 SP1 x86 | P1(ADR-001) | DEFERRED | DEFERRED（构建配置保留，首版不打包） | ADR-001 |

## 模块覆盖（以代码与 #40 夹具为准）

- Windows：账户 / 登录隐藏 / 任务 / 服务（含真实 7045/4697 临服务） / 自启动（IFEO/AppInit/LogonScript/BootExecute MULTI_SZ） / hosts（GBK） / 进程连接(+挖矿) / 哈希签名(+粘滞键) / 事件日志 / Web 日志攻击 / ADS / PS 历史（夹具隔离） / 防火墙与共享 / Mid.MySQL 日志（phpstudy/wamp/xampp 路径）
- Linux：UID0 / SSH / cron / profile / preload / hosts / systemd / 进程(+挖矿/DELETED) / SUID / 日志 / 痕迹 / Web / MySQL / hidepid 权限失败如实 / 发行版用户态矩阵
- C 级（DEFERRED / NOT_IMPLEMENTED）：深层 SAM、内核 rootkit、内存取证、磁盘镜像、ROW binlog 完整还原
