# ctfir 批量执行计划 M1→M5（无人值守全流程闭环）v1.0

> 2026-11-08 拟定，用户批准后一次性执行。本文是执行合同；与 PLAN.md v0.3 冲突时以 PLAN.md 为准。
> 执行模式：**无人值守批量**。每个 WP（工作包）结束：更新台账 → （若批准）本地 commit → STATUS.md 写精确下一步。遇到阻塞**登记后绕行或跳到无依赖 WP 继续**，不停机等待用户；只有"计划失真级"问题才停下。

## 0. 前置状态（2026-11-08 晚确认）

- M0 全绿（Win7 真机 CLI/GUI + Linux 静态，证据 TEST_RESULTS #7-#11）。
- 360 已卸载**未重启**：三个过滤驱动仍在内核（预期，重启才消失）。影响面=已绕行两点，**不在关键路径**；重启后补 #8/#9 回归。
- 构建约束不变：PE 产物一律 `D:\ctfir-build`；构建编排 bash 单行；禁 .bat 调 vcvars。
- Win7 VM(.14) ssh 可达；docker 29.4.1；CentOS 验收镜像 centos7-full:latest。

## 1. WP 列表（顺序即优先级，做完一个是一个）

### WP0 环境预检（15min）
- [ ] 复跑 M0 四项快检（驱动/ssh/docker/D盘）→ 状态写 STATUS。
- [ ] 建 `D:\ctfir-build\cmake-build\`（M1 构建目录）。
- DoD：STATUS 更新，无 BLOCKED。

### WP1 依赖锁与构建基座（T03 + CMake 正式化）
- [ ] nlohmann/json **v3.11.3** 单头 json.hpp：GitHub release 下载 → SHA256 记录 → MIT 许可全文入 licenses/ → 安全公告快查（无未修复 CVE）→ DEPENDENCIES.lock.json 转正式（去 draft）。
- [ ] CMakeLists.txt 正式工程：targets = ctfir_core(static) / ctfir(CLI) / ctfir-gui(GUI)；CMP0091 NEW + MSVC_RUNTIME_LIBRARY=MultiThreaded；WINVER/_WIN32_WINNT=0x0601；/W3 起步；bash 单行调用 VS 自带 CMake 3.31.6；**构建目录 D:\ctfir-build\cmake-build**。
- [ ] 导入审计门禁：两 EXE 导入面不得出现 UCRT/VCRUNTIME/MSVCP 类 DLL（dumpbin 自动化到脚本）。
- DoD：configure+build 全绿 + 导入审计 PASS + 单头哈希入锁文件。

### WP2 数据契约与引擎骨架（T06/T07/T08）
- [ ] schemas/v1/*.md + C++17 结构体：ScanSession / ModuleResult / Evidence / Finding / Advice（字段=PLAN §9.1）；schema_version=1；**未知大版本拒绝读取**单测。
- [ ] scheduler：模块注册表、状态机（PASS/FINDING/PERMISSION_DENIED/UNSUPPORTED/TIMEOUT/ERROR/SKIPPED，PLAN §9.2）、每模块超时预算、用户取消保 partial、JSONL 事件流、汇总文件原子替换（崩溃可恢复）。
- [ ] safe_file_reader：只读打开（FILE_SHARE_READ|WRITE）、大小上限（默认 8MB/文件、目录文件数预算）、编码探测（UTF-8/BOM/UTF-16LE/ANSI 降级标注）、行号+原文+SHA256、不跟随符号链接/junction（WIN32 遍历用带 flags 的 API）。
- [ ] 单测（Win+Linux 双跑）：状态机全路径 / 损坏 JSON / 超长行 / 超时注入 / 编码边界 / 未知版本拒绝。
- DoD：单测全绿（两平台）；GUI/CLI 尚未接入（骨架期允许占位 target）。

### WP3 Linux 纵向闭环（T09/T12/T13）
- [ ] collectors：passwd/group/sudoers(可读部分)、sshd_config+Include(范围说明)+各用户 authorized_keys(公钥指纹,不采私钥)、cron 全来源(/etc/crontab、cron.d、spool、anacron)、profile/profile.d/bashrc(用户+系统)、ld.so.preload、/etc/hosts、~/.bash_history、/proc/modules。
- [ ] rules（每条 1正2负1fault）：LNX.ACC.UID0.001 非root UID0；SSH 陌生 key/危险权限；cron 可写路径+矿池域名(stratum+tcp等)；profile 可疑命令(PROMPT_COMMAND/alias 覆盖)；preload 非空；hosts 异常映射；L13 痕迹。
- [ ] advice 七段式文本（解释/留证/复核/备份/处置/回滚/复查）——只生成文本，无执行。
- [ ] 报告：JSON + 自包含 HTML（零外部资源、全字段转义、Ctrl+F 可查、北京时间展示）。
- [ ] 测试：一次性容器内夹具（临时 docker 容器造 marker：UID0 用户/cron/hosts/history）跑正例；干净容器跑负例；`su nobody` 跑 fault（权限拒绝）。测完容器即弃，无宿主残留。
- DoD：centos7-full 容器内 `ctfir scan` 出全流程报告；规则样本矩阵入 TEST_RESULTS。

### WP4 Windows 纵向闭环（T10/T14/T15 + W13 起步）
- [ ] collectors：Task Scheduler COM（递归含隐藏、XML 留证）、NetUserEnum+NetLocalGroupGetMembers（**按 SID** 认管理员组）、Winlogon UserList、SCM QueryServiceConfig、Run/RunOnce+Shell/Userinit+IFEO+Startup+AppInit_DLLs+Winlogon\Notify+LSA Providers+Print Processors、hosts、Toolhelp 进程+TCP/UDP owner 表、BCrypt 文件 SHA256（清单含 sethc/utilman/osk/Magnify/Narrator）、EvtQuery 4624/4625 限窗。
- [ ] rules：任务可写路径/异常参数、额外管理员/隐藏账户、可疑服务、启动项可写路径、粘滞键哈希提示（无基线=待比对）、4625 Top 来源 IP、挖矿特征（stratum+tcp/矿池域名/kdevtmpfsi/kinsing）、W13 三条（web 根定位含 inetpub/常见面板路径；webshell 静态特征 php/asp/aspx/jsp；IIS 日志 Top POST IP）。
- [ ] 测试夹具（Win7 VM，全部 ctfir-marker 前缀，TASKS 夹具表登记+清理）：marker 计划任务、marker 用户($后缀)+UserList 隐藏值、hosts 行、Startup cmd、marker 服务、合成 web 根+IIS 日志样本。负例=系统自带项；fault=模拟拒绝（受限令牌路径）。
- DoD：Win7 真机 scan 全流程报告；夹具全部清理并留前后清单。

### WP5 GUI 集成（T17）
- [ ] 界面：总览(OS/SP/架构/权限/离线/只读标识)、模块列表(状态/完成来源/耗时/限制)、结果列表(搜索+风险/置信度/模块过滤)、详情(证据原文/理由/误报边界/复核/建议+复制按钮)、未完成检查页、日志页、离线帮助、输出目录选择、开始/取消。
- [ ] 约束：后台线程扫描 UI 不阻塞、状态真实计数、双击不执行证据、无任何修复入口、1024×768 可用、DPI 动态探测。
- [ ] 视觉验收：CUA 驱动 mstsc → Win7 VM 实机操作+截图核对（中文渲染/布局/点击流）。
- DoD：Win7 视觉验收通过（失败则截图+问题清单修复后复验）。

### WP6 CLI 契约（T18）
- [ ] `ctfir doctor|scan|explain|report|version`；退出码 0/1/2/3/130；stdout 纯 JSON、进度走 stderr；无 TTY/未知 TERM 不阻塞；`fix/apply` 显式拒绝。
- [ ] 测试：Win7 + centos7-full 双平台全命令矩阵 + 未知参数 + Ctrl+C 取消保 partial。
- DoD：契约矩阵全绿。

### WP7 回归与断网（T19/T20/T21 可执行部分）
- [ ] 权限对照：普通令牌 vs 管理员（Win7 VM），缺权限模块必须 PERMISSION_DENIED 而非 PASS。
- [ ] 故障注入：坏 XML/坏日志/超长行/超时；输出目录只读→提前失败不偷偷写。
- [ ] 断网验证：扫描期对自身 PID 连接抽查（netstat）无外联 + 代码级审计（不链接 wininet/winhttp/ws2_32 之外的…实际应完全不依赖网络 API）+ HTML 零外链静态检查。
- [ ] COVERAGE/硬门禁自查表（PLAN §14.5 逐条）。
- DoD：自查表全项有结论（含 NOT_TESTED 项如实列出）。

### WP8 打包交付（T23 + T24 材料）
- [ ] ZIP×2（win-x64 / linux-x86_64）：二进制+README-先读我.md+使用说明.html+SHA256SUMS+BUILDINFO.json+SBOM.json+THIRD_PARTY_NOTICES+licenses/+COMPATIBILITY.md+KNOWN_LIMITATIONS.md。
- [ ] 5 分钟验收文档（PLAN §16.2 步骤落地）。
- DoD：§16.3 硬停止清单过查；包哈希固化入 TEST_RESULTS。

### WP9 收尾
- [ ] 台账终态、夹具表清零核对、PLAN 修订记录、记忆更新。
- [ ] **若届时宿主机已重启**：补 #8/#9 回归 → 决定产物目录去留（默认维持 D:\ctfir-build）。
- [ ] 最终汇报：实际产物/哈希/已测格/规则覆盖/已知限制/未测项/验收步骤。

## 2. 横切纪律

1. 每 WP 结束：STATUS 精确下一步 + TEST_RESULTS 追加编号 + TASKS/COVERAGE 状态 + 夹具登记。
2. commit 政策：**默认每 WP 本地 commit（main，不 push）**——待用户在确认时批准/否决。
3. 阻塞协议：登记 STATUS 阻塞区 → 能绕则绕 → 跳无依赖 WP 继续 → 汇总时报。**停机条件仅限**：需要用户决策（如新授权边界）、环境彻底不可用（VM/构建双失效）。
4. 砍项顺序（时间/阻塞压力下）：WP5 视觉验收降级 selftest+截图 → W13 减到 1 规则 → B 模块字段收缩 → 其余按 PLAN §12.3。**A 模块来源、状态真实性、证据链、只读边界、发布清单不砍。**
5. 未测格如实标注：Server2008R2（无镜像）、CentOS 内核 3.10 真机、Win7 x86（ADR-001）默认保持 NOT_TESTED/DEFERRED。
6. 红线全程有效（AGENTS.md）：只读、零运行时依赖、不动 5/8 训练环境、夹具 ctfir-marker 前缀测后清理。

## 3. 预估与可中断性

- 全量 ≈ PLAN 的 44-48h 盒；无人值守连续执行，按 WP 顺序推进。**任意时刻中断可续**：新会话读 STATUS.md 即接续，已完成 WP 不重做。
- 用户回来后的验收入口：STATUS.md 顶部"当前状态" + 最终汇报。
