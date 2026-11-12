# DECISIONS（ADR）

格式：编号 / 背景 / 决策 / 理由与依据 / 影响与回退。

## ADR-011 Windows Server / AD 域控覆盖边界（2026-11-12）

- 背景：用户问遇到 Windows Server 与 AD 域控题时工具能否识别；要求把知识点找全、联网校对、在授权 VM 种夹具验证，识别失败则改工具循环直到能识别并恢复环境。
- 决策：
  1. **成员服务器上原 Windows 规则全部适用**（账户/持久化/IIS/RDP/SMB1 等）。不是 Win7 专用。
  2. **新增 WIN.AD.\* + Server 凭据防护**（GPP cpassword、NTDS 副本/IFM、SYSVOL 脚本、GPO 立即任务/scripts.ini/委派、DSRM、LDAP 签名、DC 上 Spooler/SMB 签名、WDigest/NTLMv1/LATFP 等）。不解密 cpassword，不解析 ntds.dit 哈希。
  3. **不查询 LDAP**。Domain Admins、krbtgt、DCSync ACL、非约束委派、ADCS、黄金票据仍为 C 级，手册给出手工命令。PLAN W01「域账户 ≠ 本地 SAM」维持。
  4. **授权 Win7 VM 不能变成 DC**。用 `ctfir-marker` 文件树模拟 SYSVOL/IFM + 注册表；测后 `cleanup.cmd` 恢复。不关 Spooler、不开防火墙、不动 JW2026-WIN7-01。
  5. `looks_like_dc()` = ProductType=LanmanNT 或 NTDS 服务或 `Windows\NTDS\ntds.dit` 或 SYSVOL 目录/共享。工作站仅在种了 SYSVOL 夹具时才会报 Spooler/SMB 签名。
  6. **第二轮补漏（仍不连 LDAP）**：SAM/SYSTEM hive 副本、lsass.dmp、GPP Files/Services.xml、RDP MinEncryptionLevel、RemoteRegistry AUTO、ForceGuest。活库 `system32\config` 不报。Win7 夹具 42/42 HIT → contest-fix VERIFY-GONE → cleanup 恢复（Netlogon 两项为实验机原值，检测器正确）。
- 回退：删除 `mod_w5.cpp` 注册即回到 v0.7 行为。

## ADR-010 考试兼容与「急救箱」边界（2026-11-12）

- 背景：用户问 Win7 非 SP1 / 32 位 x86 会否出现在经纬杯决赛，以及能否做成 360 式离线系统急救箱。
- 决策：
  1. **不做 RTM (7600) 兼容工程**。主线仍是 7601 SP1。运行时 `doctor`/扫描/GUI 识别 build 小于 7601 则警告，不阻断。
  2. **不交付 x86 包**（维持 ADR-001）。x64 PE 无法在 32 位 OS 启动；x86 PE 在 x64 赛机上会被 WOW64 重定向并漏 64 位持久化。有 32 位赛题证据再升级。
  3. **GUI 永不做一键修复 / SFC / DISM / 360 系统修复**。比赛急救路径 = `ctfir actions --session … --bucket clear`（或 GUI 复制命令）+ 可选 CLI `ctfir fix` 白名单。
  4. **CI 钉 `windows-2022` + VS2022**，不用 `windows-latest`（VS18）。Windows zip 用 Python zipfile（UTF-8），因 `tar -a` 在 Actions 上成功写包却退出码 1。
- 理由：决赛指南考点是持久化/账户/日志/Web，不是修系统文件。RTM 与 x86 无真机、无赛题证据，扩矩阵会挤占备考时间。
- 回退：若决赛指南或现场抽到 32 位/RTM，再开 x86 构建 + 真机格。

## ADR-009 CLI 受控 `ctfir fix`（v0.5）

- 背景：默认只读与「比赛要清持久化」之间需要一条受控写路径。
- 决策：仅 CLI `ctfir fix`；白名单操作、先备份到 `fix-backup/`、写 `fix-journal.jsonl`、`--dry-run`/`--yes`。GUI 无 Apply。
- 回退：删除 `cmd_fix` 即回到纯只读。

## ADR-008 nlohmann/json 锁 v3.12.0（2026-11-08）

- 背景：PLAN §5.1 候选 v3.11.3，开工门禁要求安全公告核查后定版；核查发现 3.12.0 修复了 3.11.3 存在的安全相关 CBOR/MessagePack 解析缺陷（OSS-Fuzz）。
- 决策：升至 **v3.12.0**（MIT，单头直含）。本机不使用 CBOR/MsgPack 解析器，暴露面另行以"解析入口限大小+仅解析自产 JSON"收缩。
- 影响：DEPENDENCIES.lock.json 已按新哈希锁定；KNOWN_LIMITATIONS 记录深嵌套递归风险余量。
- 回退：如 3.12.0 出现行为回归，按本文件流程降回并重跑哈希与门禁。

## ADR-001 Win7 x86 降 P1（2026-11-08，用户批复）

- 背景：PLAN v0.2 将 Win7 SP1 x86 与 x64 同列 P0，构建/测试矩阵×2；考试环境基本为 x64（用户实验机亦 x64）。
- 决策：x86 降 P1——构建配置保留，首版不打包不测试；有 32 位考点证据再升级。
- 影响：P0 收敛为 Win7 SP1 x64 + Server2008 R2 SP1 x64；发布说明如实标注。
- 回退：恢复 x86 P0 需重跑 x86 构建/导入审计/Win7 x86 实测。

## ADR-002 新增 Web 模块 W13（A级）与 L13 痕迹模块（B级）（2026-11-08，用户批复）

- 背景：v0.2 无 webshell/web 日志覆盖，而应急响应高频考点含"找 webshell/攻击者 IP"；执行痕迹（历史/内核模块）亦常见。
- 决策：W13（web 根定位 + webshell 静态特征 + IIS/Nginx/Apache 日志统计）纳入 48h MVP；L13（bash_history/lsmod/wtmp）为 B。W08 补 sethc/utilman 等粘滞键后门核对；W05 补 AppInit_DLLs/Winlogon\Notify/LSA Providers/Print Processors；W07/L09 补挖矿特征；W09 首规则=4624/4625 Top IP。
- 影响：M2 时间盒纳入 T25；特征命中只列证据不定罪。
- 回退：时间不足时 T25 按 §12.3 降序在 TUI 之后砍。

## ADR-003 Linux 构建用 Alpine 容器静态 musl（2026-11-08）

- 背景：v0.2 要求专用 musl C++ 交叉工具链但未指定获取途径；开发机已有 Docker Desktop。
- 决策：`docker run alpine:3.20` + `apk add g++ musl-dev`，`g++ -static` 产出 x86_64 通用基线二进制；CentOS7 用户态用 centos-ir-lab 验收；内核 3.10 真机格标 NOT_TESTED（容器为 WSL2 内核）。
- 影响：免维护 musl.cc 交叉链；构建宿主即容器，可复现（镜像 tag 固定）。
- 回退：如 Alpine 与 glibc 行为差异造成 bug，改 musl.cc 交叉链并记 ADR。

## ADR-004 CMake 锁定 VS 自带 3.31.6（2026-11-08）

- 背景：PLAN §5.1 候选 CMake 3.28 系列；开发机 VS2022 BuildTools 自带 CMake 3.31.6-msvc6，免安装。
- 决策：M1 起用 VS 自带 CMake 3.31.6，版本写入 BUILDINFO；不浮动升级。
- 影响：CMP0091 NEW / MSVC_RUNTIME_LIBRARY 静态配置照常可用。
- 回退：需要 3.28 特性行为差异时另装 3.28 并重跑门禁。

## ADR-005 Win7 VM(.14) 作为夹具与冒烟实验机（2026-11-08，用户批复）

- 决策：允许在该机放置 `ctfir-marker` 前缀夹具（假计划任务/用户/hosts 条目等），测试后清理并登记于 TASKS.md 夹具表；该机同时是 P0 目标格（SP1 x64）的真实只读扫描对象。
- 边界：不动该机其他配置；夹具清理前后清单留痕；异常中断导致残留时下次会话优先清理。

## ADR-007 开源发布获批：原创代码 MIT + 公开 GitHub 仓库（2026-11-08，用户批复）

- 背景：PLAN §4.1 将 MIT 列为提案、对外发布前需用户批准；批量计划确认时用户选择"commit+push，创建 github 开源仓库"。
- 决策：原创代码与文档按 **MIT**（LICENSE 已落库）；创建公开仓库 `Monody12/ctfir` 并随 WP 推送；第三方组件各自许可，入 THIRD_PARTY_NOTICES/DEPENDENCIES.lock。
- 边界：仓库内容推送前做敏感信息检查（无密码/凭据/私网凭据）；实验机内网 IP 与主机名属无害信息保留。
- 影响：PLAN §4.1"许可仍提案"状态终结；后续若引入 AGPL 类依赖须重新评估整包合规。

## ADR-006 PoC 直用 cl 编译，CMake 推迟到 M1（2026-11-08）

- 理由：M0 目标是"工具链能否产出可跑 Win7 的静态 EXE"，cl 直编减少生成器变量；CMake 在 M1 与 schema 一起冻结。
