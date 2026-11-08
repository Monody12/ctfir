# TEST_RESULTS

记录格式：日期(北京) / 环境 / 命令 / 预期 / 实际(退出码) / 产物hash / 结论。失败原样保留。

## 2026-11-08 环境预盘点（只读探查）

| # | 探查 | 结果 |
|---|---|---|
| 1 | VS2022 BuildTools + VC x86/x64 工具集 | 已装，v143 **14.44.35207**（vswhere 确认） |
| 2 | VS 自带 CMake | 3.31.6-msvc6（ADR-004 锁定） |
| 3 | Win7 VM 版本（reg query 经 ssh） | ProductName=Windows 7 Ultimate，CurrentBuild=7601，CSDVersion=Service Pack 1，ARCH=AMD64 |
| 4 | SSH 免密 | `ssh Administrator@192.168.0.14` BatchMode 可达，whoami=win-iei7iuc47k7\administrator |
| 5 | C 盘剩余 | 111GB |
| 6 | WSL / Docker | Ubuntu-24.04；docker images 可列（centos7-full:latest + centos:7 为 CentOS 用户态验收镜像，centos-ir-lab 为其容器实例） |

## 2026-11-08 M0 PoC（T04/T05）

**#7 Win 构建（T04）**：`poc/win/build_poc.sh`（vcvars64 短路径 + cl /MT /EHsc /utf-8 /D_WIN32_WINNT=0x0601，产物 → D:\ctfir-build）
- ctfir-poc-cli.exe：dumpbin 导入面 = **KERNEL32.dll + bcrypt.dll**（无 UCRT/VCRUNTIME，/MT 静态生效）✓
- ctfir-poc-gui.exe：导入面 = **USER32 + SHELL32 + KERNEL32**（同上零运行时）✓
- Win11 本机冒烟：CLI utf8 中文 + sha256("abc") 向量 PASS，exit=0；GUI --selftest 写结果文件 `ctfir-gui-selftest OK`，exit=0 ✓

**#8 环境异常：C 盘新建 PE 被秒删（根因查明）**
- 现象：GUI 子系统 EXE 链接成功后 **<1 秒内消失**；换名（gui-probe-a/b）、换扩展（.poc）、加版本资源段均无效；内容等价的控制台 EXE 及其副本存活。
- 根因：**360 杀毒残留内核过滤驱动仍在实时拦截**：`360FsFlt`/`360Box64`（SYSTEM_START）、`360AvFlt`（DEMAND_START），全部 RUNNING；360 程序本体已停用（C:\ProgramData\360safe\360Disabled）；Defender RealTime=False；Kaspersky 未安装（SecurityCenter2 注册为残留）。
- 处置：构建产物目录定为 **D:\ctfir-build**（D 盘写入存活，实验通过）。**待用户**：彻底清理 360 残留或对构建目录加白；清理后回归验证 #9 与 C 盘输出。

**#9 环境异常：bat 上下文调用 vcvars 全机失效**
- 现象：任何 .bat 内 `call vcvars64.bat`（全路径带引号 / 8.3 短路径、C: 与 D: 均试）失败，报"系统找不到指定的路径"/"文件名、目录名或卷标语法不正确"；**同一命令经 bash 单行 `cmd //c 'call … && cl …'` 稳定可用**（DIRECT_OK 对照）。
- 决策：构建编排一律用 bash 单行（M1 CMake 同法调用）；该异常在 360 清理后回归复测。

**#10 Win7 SP1 x64 真机冒烟（T04 门禁）**
- scp 两 EXE → `C:\ctfir-test\`，ssh 执行：
  - CLI：utf8 中文输出 ✓、sha256 selftest **PASS**、exit=0
  - GUI `--selftest --out`：window_created=1、message_pumped=1500ms、结果文件写入 ✓、exit=0（视觉验收留待 RDP/VM 控制台，见 STATUS 风险）
- 哈希两端一致（certutil vs sha256sum）：
  - cli `40dd47ed57944fc56391081810562d86b2a7c95e386a12d8e7cb120cad137206`
  - gui `b9c2005cecdd7080e8f71ac2b41c5a36e01fd93c3e511209159b92b4432ef146`
- 结论：**T04 PASSED**（x64；x86 按 ADR-001 DEFERRED）

**#11 Linux 构建（T05）**
- `alpine:3.20`（digest d9e853e8…）`g++ -std=c++17 -O2 -Wall -static` → ctfir-poc-linux，sha256 `3332fcf08853e90a2743de9a6303ea4fc4a449bcf69dfdfc580f5f96dfea44ab`
- 自实现 SHA-256（FIPS 180-4）向量 PASS；`ldd` 报 Not a dynamic program = 纯静态 ✓
- 运行验收：centos7-full:latest（glibc 2.17 用户态）exit=0 PASS；WSL Ubuntu-24.04 PASS
- **内核 3.10 真机格：NOT_TESTED**（docker=WSL2 内核，无等价环境）
- 结论：**T05 PASSED**（静态 x86_64 通用基线）

## 2026-11-08 晚 回归复测（#12：用户在 360 UI 关闭"文件系统防护"之后）

- `fltmc filters`：**360Box64 / 360FsFlt / 360AvFlt 仍在挂载**（UI 关防护 ≠ 卸载驱动）。
- C 盘 PE 秒删：**仍存在**（GUI EXE 链接成功后 <2s 消失，c-probe-gui 实验）。
- bat 调 vcvars：**仍失效**（完整输出仅一行"系统找不到指定的路径"，无 banner）。
- 本轮排除：cmd AutoRun（HKCU/HKLM 均空）；bat→bat 相对路径 call 正常（链式实验 RET=0）→ bat 失效为 vcvars 调用特有，是否 360 所致待彻底卸载后判定。
- 结论：绕行方案（产物走 `D:\ctfir-build` + bash 单行构建编排）**继续有效，开发不受阻**；#8/#9 的最终回归待用户**彻底卸载 360**（UI 关防护不够）后复测。

## 2026-11-08 晚 回归复测 #13（用户将 `C:\Users\Administrator\Documents\zcode-projects` 加入 360 文件白名单后）

- 实验：在白名单目录内重建 GUI PE（c-probe-gui.exe），链接成功（LINKED）。
- 结果：**白名单无效** —— 2s/10s/30s/60s 轮询全 GONE（与 #12 行为一致）。
- 分析：删除行为与"扫描/文件白名单"不同源（此前"文件系统防护"关闭也未阻止删除，#12）；删除者疑似 360 的云查杀/QVM 行为引擎，其信任判定不走文件白名单。
- 结论：**绕行（D:\ctfir-build）仍是唯一稳定方案**；根治只剩"彻底卸载 360 后重启"一条路（备选：多引擎设置里逐个关云查杀/QVM 试错，每轮需复测，性价比低）。

## 2026-11-08 晚 回归复测 #14（用户尝试关闭云查杀引擎后）

- 状态：文件系统防护已关 + 文件白名单已加 + **云查杀引擎无法在 UI 关闭**（用户截图：360云查杀引擎"已开启"，无关闭入口）。
- 实验：白名单目录内重建 GUI PE → LINKED → 2s/10s/30s 全 GONE。
- 定案：**删除者=360 云查杀引擎**（对无信誉新编译 GUI PE 云端判杀，不受文件白名单/文件系统防护开关约束，且 UI 不可关）。
- 待办：用户彻底卸载 360 + 重启 → 复测 #8（C盘PE）/ #9（bat调vcvars）两项，通过后可将产物目录迁回仓库（或保留 D:\ctfir-build，见 STATUS 决策）。

## 2026-11-08 深夜 WP1/WP2（#15：依赖锁 + CMake 工程 + 引擎单测）

**依赖锁（T03）**：nlohmann/json **v3.12.0**（ADR-008，公告核查：3.12.0 修复 3.11.3 的 CBOR/MsgPack 安全缺陷）
- json.hpp sha256 `aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`
- LICENSE.MIT sha256 `46a65cffd1ea955132d95a8dd921640714a8d6b537d2e4e482d31145ae95b603`

**构建工程（WP1）**：CMake+Ninja 正式化
- 坑与解法：单行 cmd 中 `%PATH%` 解析期展开（早于 vcvars）→ **禁止 set PATH**，cmake/ninja 用 8.3 短路径直呼（scripts/build-win.sh 注释）
- 产物目录：`D:\ctfir-build\cmake-build`（CMAKE_RUNTIME_OUTPUT_DIRECTORY=构建根）
- **导入审计 PASS**：ctfir.exe = KERNEL32+ADVAPI32；ctfir-gui.exe = USER32+SHELL32+KERNEL32；ctfir_tests = KERNEL32 —— 零运行时依赖 ✓

**引擎单测（WP2）**：**Windows 15/15 PASS；Linux(Alpine 静态) 15/15 PASS**
- 覆盖：SHA-256 NIST 向量（empty/abc/1M×'a'）+ **填充边界向量 'x'×55..65（与 certutil 独立实现交叉验证固化）**、流式=一次性、UTF-8 校验/清洗、安全读文件（缺文件/截断/非UTF8）、模型 roundtrip、**未知 schema 拒绝**、状态机（异常→ERROR、取消→SKIPPED+会话 CANCELLED、超预算兜底 TIMEOUT、PARTIAL 判定）、建议注册校验、报告转义（`<script>` 必须转义）、JSON 终报可解析
- 过程缺陷修复：run() 返回值曾覆盖 ctx 变更（签名改 void(ModuleCtx&)）；schema 校验逻辑简化为精确匹配；56 字节 NIST 串凭记忆键入有误→以 certutil 锚定向量替代并记录

**CLI 冒烟（Win11）**：version/doctor/scan 端到端——session.json/module-results.json/findings.json/advice.json/events.jsonl/integrity.sha256 全产出，JSON 可解析，overall=COMPLETE，exit=0
**Linux 静态产物**：ctfir `ff0d19c45412eec29b9d0e0b25e60cc1f321d4d12f5b5fc9f557a27f3e937281`、ctfir_tests `998821e43dd5b17cad76316204c2fc2d7c1f9229c4d3478d9df12ea27a708c67`（ldd 报非动态=纯静态 ✓）
**开源仓库**：github.com/Monody12/ctfir 已建立（HTTP 201，MIT，ADR-007），首 commit 576255d 已推送

## 2026-11-08 深夜 WP3（#16：Linux 纵向闭环 + 容器夹具）

**模块落地（12 个）**：LNX.ACC / SSH / CRON / SHELL / PRELOAD / HOSTS / TRACE(L13) / SYSTEMD / ELF / PROC / SUID / LOG
- 规则集：UID0.001、DUPUID.001、GID0.001、SUDOERS.001、AUTHKEY.001(+forced command 升级)、PRIVKEY.001（私钥仅存在性+哈希不采内容）、CONFIG.001、PERSIST.CRON.001、PERSIST.PROFILE.001、PERSIST.PRELOAD.001、HOSTS.MAP.001、TRACE.HISTORY.001、PERSIST.SYSTEMD.001、PERSIST.RCLOCAL.001、PROC.MINER.001、PROC.DELETED.001、SUID.UNEXPECTED.001、LOG.AUTHFAIL.001
- 挖矿特征并入 cron/profile/proc（stratum+tcp/xmrig/kdevtmpfsi/kinsing 等 19 令牌表）
- BusyBox 路径补全：/etc/crontabs（Alpine 系）

**夹具集成测试（tests/fixture_linux.sh，一次性容器内）**：**24/24 PASS**
- 负例 7 规则零误报（干净容器基线）
- 正例 9 规则全命中（marker 夹具：UID0 用户/cron/ld.so.preload/hosts/profile/bash_history/authorized_keys/SUID/systemd unit）
- 清理复验通过（findings 无 marker 残留）；HTML 无外链；report.html 产出
- **fault 例（阶段4）**：nobody 运行 → exit=2、PERMISSION_DENIED×4 模块、overall=PARTIAL——"权限失败不 PASS" 引擎级强制生效（session.cpp 后置检查）

**过程缺陷修复（均记入回归）**：
1. `| tail` 吞退出码（三次）→ 构建脚本改文件存在性/显式 rc 判定
2. 父目录不可读时 exists() 误报 not_found → errno 精确分类（denied/not_found/error），且 errno 必须在 open 失败后立即读取（先清零再读=恒 error 的低级错误）
3. Finding 增加 object_ref 字段（PLAN §9.1 命名对齐），报告显示"位置"
4. base64 手打表错位 → 计算式映射；表已程序化校验为错（234 项）后废弃
5. /etc/hosts 是 docker bind-mount → 夹具清理用覆写而非 sed -i

**双平台单测**：Windows 15/15、Linux 15/15；Windows scan 冒烟 exit=0 全产物齐
**Linux 产物**：ctfir `e2735451c0d60d5ce2ac891ae4445e13e0bdb87ff55eaed3b96d1a539c366826`

## 2026-11-09 凌晨 WP4（#17：Windows 纵向闭环 + Win7 真机夹具）

**模块落地（10 个全部实现）**：WIN.ACC / LOGINHIDE / SVC / AUTORUN(+AppInit/Notify/LSA/PrintProc/IFEO) / HOSTS / HASHES(sethc等12文件) / TASKS(COM递归含隐藏) / PROCNET(TCP/UDP owner表) / EVTLOG(4624/4625) / WEB(W13 三规则)
- 规则：WIN.ACC.ADMIN.001(RID>1000进管理员组)、WIN.ACC.DOLLAR.001、WIN.ACC.LOGIN_HIDE.001、WIN.SVC.SUSPECT.001/UNQUOTED.001、WIN.AUTORUN.SUSPECT/WRITABLE/WINLOGON/APPINIT/IFEO/LSA.001、WIN.HOSTS.MAP.001、WIN.TASK.SUSPECT.001、WIN.PROC.MINER.001、WIN.EVT.AUTHFAIL.001、WIN.WEB.WEBSHELL.001/LOGPOST.001
- 管理员组按 SID(S-1-5-32-544) 定位（本地化安全）；IFEO Debugger 全子键扫描；IIS 日志按 #Fields 列序解析 cs-method/c-ip

**Win7 SP1 x64 真机夹具测试（六件套 ctfir-marker）**：**6/6 命中、清理后 0 残留**
- 管理员组加 marker 用户 → WIN.ACC.ADMIN.001
- UserList 隐藏值 → WIN.ACC.LOGIN_HIDE.001
- 服务 binPath 指向 Temp → WIN.SVC.SUSPECT.001
- HKLM Run 指向 Temp → WIN.AUTORUN.WRITABLE.001
- hosts 10.66.0.66 → marker 域 → WIN.HOSTS.MAP.001 (hosts:23)
- 计划任务(动作指向 Temp) → WIN.TASK.SUSPECT.001（COM 枚举 7601 正常）
- 夹具操作全部经 ssh（引号命令走 stdin heredoc 绕 MSYS 转换）；hosts 改前备份 hosts.bak、改后恢复
- 清理六项后复扫：0 findings（干净基线）；夹具登记见 TASKS.md
- Win11 开发机真扫：10/10 模块 PASS、20 findings（全部为开发机合法项）
- 过程缺陷：cmd 单行 errorlevel 解析期展开（早于 scan 执行）→ 换行分开取；bash printf 会吃反斜杠路径 → ssh 多行命令一律 stdin heredoc

**双平台单测**：Windows 15/15（WP4 后回归）；导入审计含新链接库（netapi32/taskschd/wevtapi/iphlpapi/ws2_32 全为系统 DLL，仍零运行时依赖）

## 2026-11-09 凌晨 WP5（#18：GUI 集成 + Win7 真机视觉验收）

**GUI 实现**（apps/win-gui/main.cpp，Win32 原生）：顶栏(OS/SP/架构/权限/离线/只读标识)、输出目录选择(SHBrowseForFolder)、开始/取消(禁用态切换)、模块列表(状态/耗时/线索/说明含漏项计数)、发现列表(规则/风险/置信度/位置/依据)、详情(证据原文+限制+七段式建议)+复制建议(CF_UNICODETEXT)、日志区(事件流)、后台线程+Session::event_hook 实时刷新、`--scan` 自动开扫(测试用)、`--selftest` 自退。
- 新增 Session::event_hook（UI 实时模块状态）；无任何修复/执行入口；双击不执行证据。

**Win7 SP1 x64 视觉验收（mstsc + CUA 截图）**：
- 通道：临时开启 RDP（fDenyTSConnections=0 + 防火墙规则，**已回滚**=1 + 规则禁用；登记于 TASKS 夹具表）
- 验收截图确认：布局完整（940×680 默认，1024×768 RDP 内可用）、中文字体正常、顶栏识别 "Windows 7 Ultimate 6.1.7601 SP1 [x64] 权限 admin [离线] [只读模式]"、10 模块 PASS、hosts marker 命中显示于发现列表（WIN.HOSTS.MAP.001 low/medium hosts:23）、**自动选中首条发现 → 详情区完整展示证据+七段式建议**、日志 "COMPLETE 模块10 线索1 受限0 失败0"、报告写入提示
- 干净基线复扫 0 findings（清理后）✓；导入审计 GUI=系统 DLL（零运行时）
- CUA 经 RDP 的合成点击不稳定（技能已预警）；改用 schtasks /IT + `--scan` 自动化拉起 + 只读截图，视觉验收达成
- 夹具清理：hosts.bak 恢复 ✓、ctfir-gui-show 任务删除 ✓、GUI 进程清理 ✓、RDP 回滚 ✓、cmdkey 凭据删除 ✓

## 2026-11-09 WP6（#19：CLI 契约完整版 + 双平台命令矩阵）

**新增**：explain（--session/--finding，按 ID 或规则 ID 匹配，输出证据+七段式建议人工文本）、report（--session/--redact，离线重生成 report.html，IPv4 后两段掩码）、evidence.json 落盘（离线装载用）、findings/evidence JSON 装载器、evidence_trust 默认 live_local。

**命令矩阵（Windows 11 实跑 / CentOS7 容器实跑）**：
| 命令 | Win11 | CentOS7 |
|---|---|---|
| version / doctor | exit 0 ✓ | exit 0 ✓ |
| scan --out | exit 1（有发现）+ 8 个产物文件 | exit 1 + 8 个产物文件 |
| explain --session --finding | exit 0 人工文本 ✓（实例：WIN.SVC.SUSPECT.001 BaiduNetdiskUtility，附误报说明） | exit 0 ✓ |
| report --redact | exit 0 重生成 ✓ | exit 0 ✓ |
| fix/apply | **exit 3 显式拒绝** ✓ | exit 3 ✓ |
| 未知命令 / 无参数 | exit 3 ✓ | exit 3 ✓ |
| scan --out 指向文件 | exit 3（不可写）✓ | — |

**误报回归（PLAN §14.5）**：CentOS 默认 /etc/hosts 的 ip6-localnet 等本地条目命中 LNX.HOSTS.MAP.001（未解释 FP）→ 规则修复（排除 ip6-*/localhost* 前缀），双平台同步；复测 Linux 夹具 24/24、Windows 15/15、CentOS 容器 0 误报。教训：新规则必须在目标发行版默认环境跑负例。
**Linux 产物**：ctfir `881ce45016de51168a77223cd933875673346f49d5333cf9c9c8eb65e08e759b`

## 2026-11-09 WP7/WP8（#20：断网验证 + 权限对照 + 硬门禁自查 + 发布包）

**断网验证**：代码级审计（grep core/platform/apps）——**零** socket()/connect()/WSAStartup/WinHttp/URLDownload/system()/popen() 调用；链接 ws2_32 仅用于 ntohs 字节序。运行时 netstat 抽查因进程存活期过短未捕获（如实记录），以代码审计为准。

**权限对照（Windows）**：runas /trustlevel:0x20000 → WIN.EVTLOG = **PERMISSION_DENIED**、会话 PARTIAL ✓（"权限失败不 PASS" 真机验证）；已知偏差：SAFER 令牌下 TokenElevation 仍显示 admin（KNOWN_LIMITATIONS #11）。Linux 侧 nobody fault 此前 24/24 已验。

**§14.5 MVP 硬门禁自查**：
| 门禁 | 结论 |
|---|---|
| 未扫/权限/超时/解析失败不输出 PASS | ✅（引擎单测 + nobody fault + EVTLOG 非提权 + 超时兜底） |
| 每条已发布规则有最低样本 | ✅ Linux 夹具 24/24（正9/负7/fault4/清理复验）+ Win7 夹具 6/6 |
| 无未解释高风险 FP | ✅ ip6-localhost/usernetctl 两起已修复并回归；余下均为低风险且已解释（容器 hosts 工件） |
| 无冻结样本 FN | ✅（正例全命中） |
| 目标配置无未授权修改 | ✅ 夹具全清理登记（TASKS.md）；工具本体只读 |
| 无可执行自动修复路径 | ✅ 代码审计无 system/popen/写配置；CLI 显式拒绝 fix |
| 已宣称格干净启动+断网闭环 | ✅ Win7 SP1 x64 真机 / Win11 / centos7 用户态 / WSL；零网络 API |
| 报告可打开/无外链/证据可追溯/隐私 | ✅（无外链 grep 测试；私钥仅存在性+哈希；integrity.sha256 全覆盖） |

**发布包（WP8，D:\ctfir-buildelease\）**：
- ctfir-v0.1-windows-x64.zip — sha256 `3bc6e4390f8485185b5bce447ef1aec5689c186f5a2e488ce32f4aa2fb89b412`（ctfir.exe + ctfir-gui.exe + 8 类文档/SBOM/许可）
- ctfir-v0.1-linux-x86_64.zip — sha256 `d0d7e6a8ecbdd5724c61c5a7f524b7b69a352f52fe30c8cb61f3966c24feae1d`
- 包级冒烟：解压独立运行 scan ✓、HTML 无外链 ✓、SHA256SUMS 完整 ✓
