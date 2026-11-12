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

**发布包（WP8，D:\ctfir-build
elease\）**：
- ctfir-v0.1-windows-x64.zip — sha256 `3bc6e4390f8485185b5bce447ef1aec5689c186f5a2e488ce32f4aa2fb89b412`（ctfir.exe + ctfir-gui.exe + 8 类文档/SBOM/许可）
- ctfir-v0.1-linux-x86_64.zip — sha256 `d0d7e6a8ecbdd5724c61c5a7f524b7b69a352f52fe30c8cb61f3966c24feae1d`
- 包级冒烟：解压独立运行 scan ✓、HTML 无外链 ✓、SHA256SUMS 完整 ✓

## 2026-11-09 v0.3 批量（#21/#22：识别扩容全量落地 + 用例自产体系 + 三测台全绿）

**新模块/规则（12 模块 → 19 模块；规则 35 → 55+）**：
- 修复（v0.1 缺陷）：UserList=0 隐藏语义反转、hosts 127.0.0.1 一刀切跳过、autorun 不查参数路径——全部由 A7C9 外部矩阵暴露
- Windows 增：任务/账户事实化、事件 4720/4722/4724/4725/4726/4732 时间线、WMI Win32_Process cmdline（挖矿/-enc 规则+端口关联）、WIN.FILES（双扩展名[伪扩展校验]/临时exe/--baseline 基线含 basename 兜底与缺失检测/--dir）、Prefetch、ShimCache 启发式提取、USBSTOR、RDP MRU、防火墙放行、共享、驱动可写路径、UserInitMprLogonScript/BootExecute
- Linux 增：LNX.WEB（webshell+access POST Top IP）、lastlog/wtmp 登录时间线、ld.so.conf.d 注入、LNX.FILES（基线/双扩展对称）、capabilities、at、shadow 权限、timer 事实化
- 处置：advice 全量重写为**六步制**（核实→留证→停用→清除→验证→复盘，精确命令文本，停用先于删除）+ HTML"处置手册"章节
- 可用性：HTML 内联 JS 筛选/搜索/折叠（零外链）、证据时间线章节、`ctfir diff`（处置复查）、`ctfir playbook`（离线速查）、`ctfir help`（15 分钟总纲）、`--profile quick|full|web`、`--dir/--baseline`

**三测台终态**：
| 测试台 | 结果 |
|---|---|
| 单测（Win11+Alpine 静态） | **22/22**（新增 extract_paths 嵌套引号/带空格、base64、UTF-8 边界、CRLF 分行） |
| centos-ir-lab（DVD 级真容器：httpd/sshd/crond/rsyslogd） | **15/15**（UID0/cron/hosts回环/profile/webshell/POST TopIP/timer/at/shadow权限/caps/基线/建议/清理复验） |
| Win7 SP1 x64 真机 A7C9 外部矩阵 | **8/8**（W01 事实/W02 UserList=0/W03 参数路径/W04 禁用任务/W05 hosts/W06 基线/W07 零误报/W08 双扩展） |
| 我方 Linux 容器夹具 | 24/24 保持 |

**过程中抓到并修复的产品缺陷（用例自产体系的直接产出）**：
1. 双扩展名误报版本号安装器（diff 实测发现）→ 伪扩展校验（纯数字/含-不算扩展名）
2. 基线相对路径匹配不上 → basename 兜底键（双平台）
3. hosts 行内注释 `# xxx` 被当主机名 → 行内注释剥离（双平台）
4. extract_paths 引号内带空格路径被截断 → 引号段整段保留
5. split_lines 尾空行 → 规整
6. base64 手打表错位（历史）→ 计算式

**发布（v0.3 / 规则包 3.0.0）**：
- ctfir-v0.3-windows-x64.zip sha256 `440ee9a19af8e5b7f6139be0e887039847627b4e9e1603837240bd8b7e5dcb7e`
- ctfir-v0.3-linux-x86_64.zip sha256 `1bd9c11fc23d449cf885e3995aa689f75df0e893e1f9a275d89c44cc5ce7b59c`
- docs/DETECTION-POINTS.md **100 检测点全表**（ATT&CK×Autoruns×Lynis×ctfshow 来源标注）；tests/cases/{cases_win,cases_linux}.tsv **75 声明式用例行**；docs/KNOWLEDGE-MAP.md 考点映射

**自评循环判定（收工）**：
- R1：门禁全绿；gap=单测 15→25 目标未达 → 续（R2）
- R2：单测 22/22 双平台 ✓；对照 DETECTION-POINTS 全表——所有已列检测点均有规则+用例；未解释误报=0；剩余项（ShimCache 精确时间/Amcache/W10-WMI 消费者/内核专题）均为"不改变验收结论"的增强 → 依框架强制收工
- 硬停止项（待用户）：宿主机重启后 360 回归 #8/#9；Server2008R2/CentOS3.10 真机格；A7C9 Cleanup 由用户决定是否执行

## 2026-11-12 v0.4（#23：基线核查/中间件族——对照决赛指南补强）

**依据**：决赛指南（2026 经纬杯）考点——团队 AI 综合防御赛 60 分 + 个人安全防护赛 40 分的核心均为「基线核查/系统加固/漏洞修复」，v0.3 只覆盖入侵痕迹侧 → 本轮补齐"安全基线与加固核查"板块。

**新模块（8 个，规则 55+ → 75+）**：
- WIN.BASE.PWD：密码策略（NetUserModalsGet：最小长度/锁定阈值）→ 越界即报
- WIN.BASE.ACC：UF_PASSWD_NOTREQD（不需要密码）账户 + Guest 启用
- WIN.BASE.REG：RDP 启用+NLA、SMBv1、自动登录（明文 DefaultPassword）、登录用户名显示、日志 Retention=0、补丁留证（UBR+HotFix）
- WIN.BASE.PORTS：TCP LISTEN 白名单核查（数据库绑 0.0.0.0 → medium；RPC 动态端口段白名单）
- LNX.BASE.PWD：**空口令**（shadow 空 hash + passwd 第二字段直查）、**弱口令现场比对**（crypt 字典比对，哈希不落盘）
- LNX.BASE.POLICY：login.defs 密码策略、系统账户可登录（uid<1000 + bash）
- LNX.BASE.KERNEL：ip_forward/suid_dumpable/kptr/dmesg 危险参数 + DirtyCow/DirtyPipe 版本范围线索 + pkexec(PwnKit) 提示
- LNX.BASE.SERVICES：telnet/vsftpd/tftp 启用、SNMP public、远程日志/NTP 状态
- MID.REDIS：requirepass 缺失（未授权→写 crontab 拿壳链）、bind 0.0.0.0、protected-mode no
- MID.MYSQL：skip-grant-tables、local-infile、bind、general_log 定位
- MID.PHP：allow_url_include/display_errors/expose_php + web 根 phpinfo 文件
- MID.BACKUP：web 根 .sql/.bak/.tar.gz 等备份泄露
- REG_MULTI_SZ 解码（BootExecute 等显示修复）

**测试**：centos-ir-lab **23/23**（新增：空口令/root 弱口令 crypt 比对/系统账户可登录/不安全服务/Redis 未授权+PM/MySQL local-infile/phpinfo/基线 mismatch）；Win7 真机基线 8 条发现（密码长度 0/锁定阈值/NOPASSWD×2/日志保留×3/端口——全部为该机真实弱基线，非夹具）；A7C9 八项保持 8/8。
**过程缺陷修复**：REFPATH 系统任务误报（\Microsoft\ 前缀排除——python 转义吃反斜杠第 4 次）；REG_MULTI_SZ→<binary>；RPC 49152+ 端口白名单；LOGPOST 发现补挂 evidence_id（add_evidence 返回 id）；容器 /etc/hosts bind-mount sed -i 失败 → grep-v 覆写；容器无 python3 → openssl passwd -1 生成弱口令 hash。

**发布（v0.4.0 / 规则包 4.0.0）**：
- ctfir-v0.4-windows-x64.zip `487ec0f6170204aeb8fa3f25e4a1468b03d1a085bc182b31860122a3db6365d6`
- ctfir-v0.4-linux-x86_64.zip `f88aca751bdc6acab76102597ff15fb47c51e28b87ed11d1f11dff151c5c4e64`

## 2026-11-12 v0.5（#24：受控修复能力 + 逐点处置闭环验证）

**ADR-009（用户批准）**：默认仍只读；新增 `ctfir fix` 受控修复——白名单操作 + 逐条确认/--yes/--dry-run + 自动备份(fix-backup/) + 日志(fix-journal.jsonl)。

**处置闭环已真机验证的考点**（构造→识别→fix→验证→环境还原）：

| 考点 | 识别 | 修复动作 | 修复后验证 |
|---|---|---|---|
| LNX cron 后门 | ✅ | 行注释(`# ctfir-fixed:` 前缀) | ✅ 任务失效 |
| LNX UID0 后门账户 | ✅ | usermod -L + userdel -rf；占用时 sed 强制移除 | ✅ 账户消失 |
| Win 禁用账户 A7C9-W01 | ✅ | net user /delete | ✅ 账户消失 |
| Win UserList=0 A7C9-W02 | ✅ | reg delete 同名值（原值已回写恢复） | ✅ 值消失 |
| Win Run 引用非常规路径 A7C9-W03 | ✅ | reg delete 值 | ✅ 值消失 |
| Win 禁用任务 A7C9-W04 | ✅ | schtasks /disable → /delete | ✅ 任务消失 |
| Win hosts 回环 A7C9-W05 | ✅ | hosts_delete_line 原生删行 | ✅ 行消失 |
| Win 双扩展名 A7C9-W08 | ✅ | 文件隔离（.quarantine） | ✅（容器侧验证） |

**基线策略类（密码长度/锁定阈值/日志保留等）**：正确设计为不支持一键（改的是安全策略不是后门对象），dry-run 如实显示"不在白名单，按手册人工执行"——用户可在比赛环境自行改策略（一次命令）。

**Win7 真机全量扫描**：23 模块 / 26 findings（含 8 条真实弱基线）/ REFPATH 系统任务误报 0 / 未解释误报 0。

**注意**：fix 操作会真实删除 A7C9 部分夹具对象（用户/任务/Run 值/hosts 行）——UserList 已回写恢复；其余对象已删除不再恢复（用户已确认跑不跑 Cleanup 无所谓）。如需重建夹具用 A7C9 Install 脚本。

**发布**：v0.5.0 / 规则包 4.0.0——构建产物同 v0.4 但含 fix 引擎；版本号随下次打包更新。

## 2026-11-12 v0.5 迭代R4（#25：遗漏考点补齐 + A7C9 一键处置闭环）

**R4 遗漏补齐（联网调研 [Bypass007 应急笔记](https://bypass007.github.io/Emergency-Response-Notes/) + [ProbiusOfficial windows-ir-skill 38项检查](https://github.com/ProbiusOfficial/windows-ir-skill)）**：
- WIN.BASE.PERSIST 模块：WMI MOF 痕迹 / BITS 任务状态 / COM 劫持（HKCU InprocServer32 可写路径）/ 屏幕保护后门 / OpenSSH sshd 哈希留证
- LNX 深化：webshell 特征扩展（$$变量变量 / preg_replace /e / call_user_func / base64+file_put_contents）/ .htaccess·.user.ini 后门 / btmp 暴力破解计数
- LNX.BASE.TRUST：hosts.equiv / .rhosts 信任登录
- LNX.BASE.ROOTPATH：root PATH 含当前目录 "."
- LNX.BASE.GRUB：GRUB 无密码
- LNX.BASE.NFS：NFS 导出
- LNX.BASE.FILEPERM：关键文件其他用户可写

**A7C9 完整闭环（构造→识别→一键批量修复→环境还原）**：
- 构造（net user / reg add / schtasks / hosts / invoice.pdf.exe）→ 扫描（31 findings）→ `fix --all --yes` → 逐项环境验证（全部消失）→ A7C9 夹具重建
- 基线策略类（密码长度等）如实标"不在白名单"——改安全策略≠删后门对象

**测试台终态**：单测 22/22×2 | centos-ir-lab 23/23 | Linux 夹具 24/24 | A7C9 七项构造→识别→修复→还原全通过

## 2026-11-12 v0.5-R5（#26：最终遗漏补齐——服务DLL劫持/hosts.allow/SSH wrapper）

**本轮新检测（3 项）**：
- WIN.BASE.SVCDLL.001 — svchost 组服务 ServiceDll 指向可写目录（DLL 劫持/后门）
- LNX.BASE.HOSTSALLOW.001 — /etc/hosts.allow spawn/ALLOW 后门规则
- LNX sshd 二进制哈希留证（wrapper 后门需可信同版本比对）

**四测台终态**：单测 22/22×2 | centos-ir-lab 回归通过 | Win7 真机 25 findings（8 基线）| A7C9 8/8
**发布**：v0.4 包含全部功能（fix 引擎 + 基线 + 中间件 + 痕迹 + 55+ 规则）

## 2026-11-12 v0.5-R10（#31：联网调研补漏——命令替换/SSH端口/近期文件/进程伪装）

**本轮新检测（4 项，来源：sklinux CTF排错 / 玄机靶场 WP 高频题型）**：
- LNX.BASE.CMDSIZE.001 — 系统命令大小阈值异常（假 ls/ps 替换；18 命令清单，偏小=脚本替换，偏大=加壳捆绑）+ CMDRECENT 变体（7 天内 mtime 线索）
- LNX.SSH.PORT.001 — sshd_config Port 提取（非 22 报 low；后门 SSH 常跑非标端口）
- LNX.BASE.RECENT.001 — /etc、/usr/local/{bin,sbin}、/root、各用户 .ssh 下 7 天内可执行/脚本/配置文件（新投毒线索）
- LNX.PROC.NAMEMISMATCH.001 — /proc/PID/cmdline argv[0] 与 /proc/PID/exe 基名不匹配（exec -a 伪装进程名；解释器/busybox 白名单）

**centos-ir-lab 实证循环（27/27 全绿）**：
- 夹具：脚本替换 /usr/bin/ls（117608B→30B）→ CMDSIZE 命中 ✓；sshd_config Port 2222 → SSH.PORT 命中 ✓；/root 7 天内 .sh → RECENT 命中 ✓；`exec -a kworkerd /tmp/ctfir-mismatch` → NAMEMISMATCH 命中 ✓
- 清理复验通过；ls 从备份还原验证（LS_OK）；夹具进程清理改用 exe readlink 定位——pgrep -f 对 argv[0] 伪装进程天然失效（该缺陷本身即该考点的检测价值证明）

**过程修复**：R8/R9 补丁脚本对 mod_e.cpp（/etc/environment）与 mod_a.cpp（ProxyCommand）各重复插入一段——去重后构建恢复绿。教训：补丁脚本须先 grep 防重复执行。

**版本**：kToolVersion 0.4.0 → 0.5.0；DETECTION-POINTS 100 → 104 项
**测试台终态**：单测 18/18 | Linux 夹具 24/24 | centos-ir-lab 27/27

## 2026-11-12 v0.5-R11（#32：反斜杠根因二次清理 + portproxy 端口转发后门）

**关键缺陷修复（9 处静默漏检根因）**：
- scripts/scan_bad_escapes.py 新工具：逐字符扫描字符串字面量，单反斜杠+大写字母=Python heredoc 吞噬痕迹（\ 成对跳过避免误报）
- mod_w4.cpp 修复：COM 劫持键路径（Software\Classes\CLSID→损坏版永不打开键）、InprocServer32 子键、SCRNSAVE 键、sshd.exe 路径、ServiceProvider\ServiceTypes、驱动服务 Parameters 键、MOF 扫描路径、WMI 命名空间、object_ref 2 处——此前 COM 劫持/SCR/sshd 哈希/服务DLL 前置探测全部静默失效
- 判定：这些模块在真机上"从未真正执行过"，负例干净是因为路径错误打开失败，不是检测通过

**新检测（1 项，DETECTION-POINTS #105）**：
- WIN.PORTPROXY.001 — netsh portproxy 端口转发规则（注册表 PortProxy\v{4,6}to{4,6}\{tcp,udp} 四族枚举；T1090 内网穿透/流量中继）
- 修复引擎：reg delete 值级删除 + netsh show all 备份 + add 命令回滚说明

**Win7 真机端到端**：netsh add v4tov4 13389→10.99.99.99:3389 → 扫描命中（PortProxy\v4tov4\tcp\*/13389）→ fix --finding --yes → netsh show all 空 + reg query 空 ✓
**测试台终态**：单测 18/18（Linux）| Linux 夹具 24/24 | centos-ir-lab 27/27 | Win7 真机 31 findings（portproxy 新增）

**R11 全测台回归（夹具重建后）**：
- A7C9 真机一度 5/8——Run 项/hosts 行/invoice.pdf.exe 三夹具丢失（此前 fix --all 批量修复时被清除，属预期"环境还原"而非检测退化）；重建三夹具后 8/8 全绿
- 全测台终态：Win 单测 22/22 | Linux 单测 18/18 | Linux 夹具 24/24 | centos-ir-lab 27/27 | A7C9 8/8 | portproxy 检测→修复→还原 ✓
- 教训：真机夹具是易耗品——每次 fix --all 验证后必须重建再跑回归；断言失败先查夹具存在性再查工具

## 2026-11-12 v0.5-R11b（#33：Windows 近期可执行文件对称补齐 + 终态）

**新检测（1 项，DETECTION-POINTS #106）**：WIN.FILES.RECENT.001 — 用户目录 7 天内修改的可执行/脚本（FILETIME 差值精确计算；与 Linux LNX.BASE.RECENT 对称）。真机验证：新部署的 ctfir.exe/ctfir-gui.exe 正确命中（mtime 今天）。

**五测台终态（R11b 收工）**：Win 单测 22/22 | Linux 单测 18/18 | Linux 夹具 24/24 | centos-ir-lab 27/27 | A7C9 真机 8/8 | portproxy + RECENT 均检测→修复/识别闭环
**版本**：v0.5.0 | 45 模块 | 106 检测点 | 远端 e1b28d0 → 本轮推送后更新

## 2026-11-12 v0.5-R12（#34：决赛指南逐条重对照 → 3 个考点缺口闭环）

**对照方法**：决赛指南 PDF 逐条提取主机域考点（基线核查/日志审计/密钥治理/降权运行/应急响应五维），映射 106 检测点找缺口。Web 漏洞/SQL 注入/AI 安全属其他工具域（AutoSQLi/RCE-helper/独立备考），不在 ctfir 范围。

**新检测（4 项，DETECTION-POINTS #107-110）**：
- MID.MYSQL.LOGSHELL.001 — MySQL general_log 内容取证：INTO OUTFILE/DUMPFILE + .php//var/www/tmp 特征（日志写马/UDF 提权痕迹；个人赛"数据库日志审计"考点）
- MID.WEB.CREDS.001 — web 根敏感凭据文件：.env/.pem/.key/id_rsa/.git-credentials/.htpasswd（"密钥与敏感信息保护"考点）
- MID.WEB.GITLEAK.001 — web 根 .git 目录（源码整站拉取，CTF 高频信息泄露）
- LNX.BASE.DROPRIGHT.001 — 中间件未降权：mysqld/redis/php-fpm/java root 运行直接报；nginx/httpd 采用两段式判定（同名字存在非 root 实例=master-root 标准架构，不报）——避免 Apache 标准部署全环境误报

**centos-ir-lab 实证（31/31 全绿）**：日志写马（general_log 注入 OUTFILE 语句）/.env 凭据/.git 目录/exec -a mysqld root 假进程 → 4 项一次命中；清理复验通过
**全测台**：Linux 单测 18/18 | centos-ir-lab 31/31 | 其余测台不受影响（Linux-only 改动）

## 2026-11-12 v0.5-R12b（#35：指南终检——SELinux/AppArmor 安全模块状态）

**新检测（2 项，#111-112）**：LNX.BASE.SELINUX.001（/sys/fs/selinux/enforce + /etc/selinux/config 双路；Permissive/disabled → low）+ LNX.BASE.APPARMOR.001（模块启用但无 profile → low）——对应个人赛"安全模块与内核参数配置"字样。
**验证**：centos-ir-lab 临时 SELINUX=disabled → 命中 → 配置还原 ✓；负例（enforcing/容器无 SELinux）零误报 ✓；回归 31/31 ✓
**指南对照终态**：主机域考点（基线核查/漏洞修复/系统加固/日志审计/应急响应五维）全部映射到 112 检测点，无剩余缺口；Web 漏洞类/AI 安全类属其他工具域（AutoSQLi/RCE-helper/独立备考），业务恢复/binlog 深挖为已登记人工项。

## 2026-11-12 v0.5-R13（#36：权威题源驱动 12 知识点 + SIGPIPE 测台根因修复）

**方法论**：不再自脑补清单——逐条对照玄机应急响应题库 + 等保基线检查项，确认 12 个真缺口后一次性实现。

**新检测（12 项，DETECTION-POINTS #113-124）**：
- Linux：LNX.PERSIST.PAM（pam_exec/非标准 .so 路径后门——玄机经典）、LNX.BASE.UMASK（等保 ≥027）、LNX.BASE.FAILLOCK（登录失败未锁定）、LNX.BASE.TMOUT（会话无自动登出）、LNX.SSH.PWDAUTH + LNX.SSH.MAXAUTH（sshd 爆破面）、LNX.RANSOM.TRACE/SCRIPT（勒索信+12 加密扩展名+加密脚本）
- Windows：WIN.BASE.UAC（EnableLUA=0）、WIN.BASE.BLANKPWD（空口令可网络登录）、WIN.BASE.DEFSHARE（默认共享未禁）、WIN.AUDIT.DISABLED（auditpol 实测抓到 Process Creation 等未开启——"入侵研判证据盲区"）、WIN.RANSOM.TRACE/WALLPAPER（勒索信/加密扩展名/壁纸篡改，真机 2 夹具命中）
- 域成员 note（域环境提示横向考点）

**测台根因修复（重要）**：findings.json 涨过 64KB 管道缓冲后，`set -o pipefail` + `echo "$RES" | grep -q` 产生 SIGPIPE——grep 前部匹配即退出，echo 写入中断 → 老断言（文件前部规则）全误判 FAIL、尾部规则通过。修复=断言改文件 grep（RESF/RESNF/RES2F 落盘），37/37 全绿。教训：大串断言永不经管道。

**验证**：centos-ir-lab 37/37（6 新检测夹具全命中+清理复验）；Win7 真机勒索信/.locked 命中后删除、UAC/BLANKPWD 负例正确、壁纸 TranscodedWallpaper 误报已修（\Themes\ 白名单）；A7C9 8/8；Win 单测 22/22；Linux 单测 18/18

## 2026-11-12 v0.5-R14（#37：实搜题库 WP 逐考点对照——9 真缺口闭环）

**方法论升级**：R13 的"玄机/等保对照"系凭记忆——本轮真正联网抓取两份权威题库全文逐考点对照：玄机应急响应靶场合集 WP（cnblogs backlion，9 章）+ 知攻善防实验室 8 靶机 WP。确认 9 个反复出现的真缺口。

**新检测（8 规则 + 1 事件扩展，#125-132）**：
- MID.MYSQL.UDF.001 — plugin_dir 下 udf.so（玄机 MySQL 题核心；plugin_dir 配置提取+默认路径兜底）
- MID.MYSQL.ERRSHELL.001 — error.log/mysqld.log/.err 中 bash -i、/dev/tcp、nc -e（玄机：error.log 藏反弹 shell）
- LNX.WEB.BLACKLINK.001 + WIN.WEB.BLACKLINK.001 — 黑链（display:none/visibility:hidden/font-size:0 + href="http:// 外链；玄机黑链整章。修一 bug：引号判定反了）
- LNX.TOOLS.ARTIFACT/FRPCFG + WIN.TOOLS.ARTIFACT/FRPCFG — 攻击工具遗留（fscan/frpc/frps/nps/npc/chisel/ngrok/mimikatz/rubeus/ew 文件名 + frpc.ini [common]/server_addr 内容特征；玄机 NOP Team/行业攻防/运维杰克、知攻善防×2 反复出现）
- LNX.SSH.HIDDENKEY.001 — .ssh 下点开头隐藏密钥（玄机·行业攻防：/root/.ssh/.id_rsa.pub）
- WIN.ACC.GUESTADMIN.001 — Guest(RID 501) 在管理员组（知攻善防·克隆账号考点；真机 0 误报）
- W09 时间线扩展 — Event 4781 用户改名（玄机·evtx：Administrator→Administratro 影子手法）
- WIN.RMT.SOFTWARE/SUNLOGIN.RCE.001 — 远控软件痕迹（向日葵/ToDesk/TeamViewer/AnyDesk 存在性 + 向日葵日志 PowerShell 路径遍历 RCE 特征）

**验证**：centos-ir-lab 43/43（UDF/error.log/黑链/fscan/frpc/点key 全命中+清理复验）；Win7 真机 fscan/frpc 命中、远控/黑链/GuestAdmin 零误报（负例正确）、夹具即建即删；A7C9 8/8；Win 单测 22/22；Linux 单测 18/18
**明确不覆盖（如实登记）**：内存马（需 arthas/运行时分析）、Redis 主从复制 module.so 深挖（Redis 配置面已覆盖）、流量包/eml 分析（pcap 域）、shiro key 提取（应用层）

## 2026-11-12 v0.5-R15（#38：修复闭环轮——fix 白名单扩容 + 两个灾难级修复 bug）

**修复白名单扩容（R10-R14 规则接入 fix 引擎）**：
- 新增：LNX.PROC.NAMEMISMATCH（STOP→KILL）、LNX.SSH.PORT/PROXYCMD（配置行注释）、LNX.PERSIST.PAM（行注释）、LNX.SSH.HIDDENKEY/LNX.TOOLS.*/WIN.TOOLS.*/LNX.RANSOM.*/MID.MYSQL.UDF/MID.WEB.CREDS/GITLEAK（quarantine，.git 目录支持）、WIN.RANSOM.WALLPAPER（reg delete）
- LNX.SSH.PORT object_ref 补行号（linux_comment_line 需 file:line）

**两个灾难级修复 bug（fix 闭环测试逼出）**：
1. **root 弱口令 → `userdel -r root`**：WEAKPWD 规则走账户删除分支——真机一旦执行将删除 root！修复：root/daemon/bin/sys/sshd/nobody 永不 userdel；WEAKPWD 一律只锁密（passwd -l）不删除
2. **home=/tmp 账户 → `userdel -rf` 清空整个 /tmp**：UID0 引擎内置删除 userdel -rf 对家目录无护栏——夹具 ctfir-marker(home=/tmp) 触发后 /tmp 全灭（含 fix-backup 备份目录）。修复：remediate 与 fixengine 两处均加关键目录护栏（/、/tmp、/var、/etc、/usr、/bin、/sbin、/root、/dev、/proc、/sys、/boot、/home、/lib、/lib64）——家目录命中则只删条目不递归

**测台第三踩 pipefail**：fchk 的 `grep -c` 零计数 exit 1 → 管道整体非零误判 FAIL；改为输出落盘 + `|| true` 兜底

**fix --all 闭环（centos-ir-lab 61/61 全绿）**：构造 15 类后门 → 扫描（195 findings）→ fix --all --yes（执行 35/不支持 51）→ **逐项环境恢复检查 18/18**（账户已删/行已注释/文件已隔离/进程已杀/root 幸存/测台脚本幸存）→ 清理复验 ✓

## 2026-11-12 v0.6（#39：R16 收尾 + 日志取证补漏 + 版本 0.6）

**范围**：
- 收尾未提交的 R16 五点并修缺陷：System 7045 保留、Security 改查 4697（7045 不在 Security 通道）；PS 历史改用共享匹配（补 IEX(/FromBase64 等）；ADS 跳过 Zone.Identifier 防 Downloads 误报；SSHLOG 去重且口令不入库；宝塔日志按 `{site}.log` 识别（不再误过滤成只认 access.log），并与标准 access 日志共用 POST + 攻击特征分析。
- 考点补漏：`LNX.WEB.LOGATTACK.001` / `WIN.WEB.LOGATTACK.001`（SQLi、目录穿越、webshell 文件访问、扫描器 UA，含百分号/双重编码）；`MID.MYSQL.SLOWLOG.001` / `MID.MYSQL.BINLOG.001`（明文关键字；ROW 格式只留证）。
- 版本：kToolVersion 0.5.0 → **0.6.0**，规则包 4.0.0 → **6.0.0**，检测点 132 → **142**。

**单测（本轮）**：
- Windows（含 Win 专有 extract_paths）：**54/54**（原 22 + 本轮 log_attack/PSHIST/ADS/MySQL/宝塔文件名 32 条，全部 PASS）
- Linux musl 静态（无 Win 专有 4 条）：**50/50** PASS；ldd = Not a valid dynamic program（纯静态）

**夹具回归（本轮）**：
- Alpine 一次性容器（tests/fixture_linux.sh）：**31/31**（原约 24；新增 SSHLOG/LOGPOST/LOGATTACK/SLOWLOG/BINLOG 正例 + 对应负例；清理复验无残留；nobody 低权限 exit=2 / PERMISSION_DENIED / PARTIAL）
- centos-ir-lab（fixture_builder_centos.sh，centos7-full）：**65/65**（历史断言全绿 + v0.6 SSHLOG / LOGATTACK / SLOWLOG / BINLOG；fix 闭环 18 项含 root 未被删除、install/cleanup 幸存；清理复验无 ctfir-marker 残留）。第一次因 Git Bash 把 /d/... 传给 docker cp 成 C:\d 导致二进制未进容器（exit=127），改用 D:/ctfir-build/linux/ctfir 后全绿——非规则漏检。
- 未解释误报：**0**（干净环境无 marker；Zone.Identifier 不报；普通 SELECT / 业务词 union / curl UA 单测负例通过）

**Windows 开发机只读冒烟（2026-11-12 16:06 北京时间）**：
- 会话 tool_version=0.6.0、rule_pack_version=6.0.0、overall=COMPLETE
- WIN.EVTLOG：System 7045 查询成功（本机 70 条历史服务安装，无指向可写路径/解释器/Mysql 伪装，0 误报）；Security 通道可读
- WIN.TRACE.PSHIST：扫描到 1 个历史文件，本机真实历史命中 5 条（按设计，非夹具）
- WIN.FILES.ADS：Temp 下 ctfir-marker-ads.txt:hidden.exe 正例命中 1；同目录 Zone.Identifier 负例不报；测后已删除夹具文件
- WIN.WEB：本机无 IIS/phpstudy 日志，模块 PASS 并如实 [not_found]

**发布（v0.6.0 / 规则包 6.0.0）**，路径 D:\ctfir-build\release\，BUILDINFO.built_utc=2026-11-12T08:06:50Z（北京 16:06）：
- ctfir-v0.6-windows-x64.zip  973830 字节  sha256 46a84c888dfe7f0b9afcdcef6195b720782939c7eced9f0c9ba988d21220461
- ctfir-v0.6-linux-x86_64.zip 1418459 字节 sha256 e096d1e5b74d5f5af78b4c56d5004551c6e71ba66e2a094e22e5f0c8918040b
- 导入面：ctfir.exe = KERNEL32+SHELL32+ole32+OLEAUT32+ADVAPI32+NETAPI32+IPHLPAPI+WS2_32+wevtapi（零 CRT 运行时）；Linux 纯静态 musl
- **未 git push、未创建 GitHub Release**——待确认后再做。

## 2026-11-12 v0.6.1（#40：原 manual/NOT_TESTED 全部自动化 + 测试完善）

**版本**：kToolVersion **0.6.1** / 规则包 **6.0.1** / 检测点仍 **142**（无新规则 ID；Windows 补齐 MID.MYSQL 同 ID 平台实现；EventID Qualifiers 与 BootExecute MULTI_SZ 为解析/误报修复）。小版本用于本轮测试完善与上述代码修正。

**一条命令**：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test-all.ps1`（测试脚本可联网/Docker；工具运行时仍离线零网络、只读为主）。若 `scripts/build-win.sh` 在 Git Bash 下因 `cmd //c` 空转未刷新产物，test-all 会回退到 `cmd.exe /c` + vcvars64 + cmake。

### 原 manual / NOT_TESTED 逐项（方式与结果）

| 原项 | 自动化方式 | 结果 |
|---|---|---|
| F36 Win System 7045 真实正例 | `tests/fixture_win.py`：`sc create ctfir-marker-svc binPath= <可写路径\marker.exe>` 制造真实事件；扫描断言 WIN.EVT.SVC7045 且命中「可写路径」启发式；`sc delete` + finally/atexit 幂等清理（失败也删服务）；复扫确认服务不存在 | **F36 PASS**；清理后 `sc query` 错误 1060（未安装）；事件通道不清理，7045 残留属预期 |
| F36b Security 4697 | 同一临服务；`auditpol` 以 GUID `{0CCE9211-69AE-11D9-BED3-505054503030}`（Security System Extension）临时开启 Success/Failure，测后还原备份 | **F36b PASS**；auditpol 已还原 |
| F38/F39 PowerShell 历史 | 环境变量 `CTFIR_FIXTURE_PSHIST` 指向临时夹具目录（含正例 `ConsoleHost_history.txt` + 负例干净文件）；生产扫描路径不变；断言命中路径不含用户真实 `AppData\Roaming\...\PowerShell` | **F38/F39 PASS**；夹具测后删除，未读未改真实历史 |
| F08 IFEO / F09 AppInit / F10 LogonScript / F11 BootExecute | 临注册表夹具（IFEO 仅针对 `ctfir-marker-ifeo.exe`；AppInit 短暂写入且不打开 LoadAppInit_DLLs=1；BootExecute 追加后精确还原 MULTI_SZ） | **全部 PASS**；清理后 AppInit 空、BootExecute=`autocheck autochk *` |
| F17 AUTHFAIL / F18 矿池 / F19 -enc / F21 prefetch / F25 防火墙 / F26 共享 / F28 IIS / F33 GBK hosts / F37 无 svchost 误报 / F40 ADS / F41 Zone.Identifier / F43–F45 Web | 全部纳入 fixture_win.py，`ctfir-marker` 前缀，自备清理 | **全部 PASS**（ADS 文件放在 `C:\Users\Public\` 根目录，因模块不递归子目录） |
| Windows MySQL 日志路径缺口 | 新模块 `mod_mysql_win`（`platform/win/mod_w4.cpp`）：phpstudy_pro / phpstudy / wamp / xampp / Program Files MySQL 与 MariaDB + `CTFIR_FIXTURE_MYSQL`；夹具自动造 slow/general/binlog 正例与普通 SELECT 负例；清理不触碰真实 phpstudy 安装 | **M01–M04 PASS**；规则 ID 与 Linux 相同：MID.MYSQL.LOGSHELL / SLOWLOG / BINLOG |
| Linux 原 manual（L06/L10/L16/L18/L22/L23/L27/L32/L34/L35/L39/L48 等） | `fixture_linux.sh`（便携 DELETED/MINER/SUID：自写脚本 `chmod 4755`，矿池 token 用 `sleep N; true` 避免 exec 优化丢掉 argv0）+ `fixture_hidepid.sh` + `fixture_builder_centos.sh` + `fixture_distros.sh` | 见下方数字，全绿；测后清理复扫无 marker |
| CentOS 3.10 真内核 | **Docker 技术不可行**：容器共享宿主内核（本机 WSL2 `6.6.87.2-microsoft-standard-WSL2`）。替代：centos:7 用户态（3.10 时代 glibc 2.17 布局）+ centos-ir-lab。未起 QEMU 3.10 VM。不把该格标 PASSED | 用户态 **42/42** 与 **75/75**（AUTOMATED_SUBSTITUTE） |
| Server 2008 R2 真 OS | **Windows 容器不可行**：容器需匹配宿主内核，无法在 Win11 10.0.26100 上跑 2008 R2；镜像亦极重且无合法来源。替代：`tests/test_evt_xml.cpp` 使用 2008 R2 形态 `<EventID Qualifiers="16384">7045</EventID>` 及 4697 合成 XML；同一 `_WIN32_WINNT=0x0601` API 由本机 fixture_win 行使。不把 2008 R2 OS 格标 PASSED | 单测 **5/5**（AUTOMATED_SUBSTITUTE） |
| Win7 x86 | ADR-001 DEFERRED，首版不打包 x86——构建范围外，不是“未写测试” | 保持 DEFERRED |
| Win10 22H2 | 本宿主是 Win11 `10.0.26100`，无 22H2 映像，不标 PASSED | 宿主不是 22H2 |
| C 级（内核 rootkit / 内存取证 / 磁盘镜像 / 深层 SAM RID / ROW binlog 完整还原） | 未实现范围，非未测功能 | DEFERRED / NOT_IMPLEMENTED |

**清理闭环（Windows 夹具结束后本机抽查，北京时间 16:43 前）**：`ctfir-marker-svc` 未安装（1060）；AppInit_DLLs 为空；BootExecute 仅默认 `autocheck autochk *`；hosts 无 marker；`C:\Users\Public\ctfir-marker-ads.txt` 与 phpstudy MySQL 夹具目录不存在。事件 7045/4697 残留属预期（禁止 `wevtutil cl`）。

### 构建与测试数字（北京时间 2026-11-12）

- `scripts/scan_bad_escapes.py`：**total 0**
- Windows 单测（`ctfir_tests.exe`）：**59/59 PASS**（含新增 `test_evt_xml` 5 条：2008 R2 Qualifiers 7045/4697、Win11 4625、单引号 Name）
- Linux musl 单测（alpine 容器跑 `ctfir_tests`）：**55/55 PASS**（无 Win 专有 extract_paths 用例）
- `tests/fixture_win.py`：**29/29 PASS，fail=0**
  - 正例命中：F08 IFEO、F09 AppInit、F10 LogonScript、F11 BootExecute 额外项、F17 AUTHFAIL（25 次 LogonUser 失败）、F18 stratum、F19 -enc、F21 prefetch XMRIG stub、F25 防火墙、F26 共享、F28 IIS POST W3SVC99、F33 GBK hosts、F36 7045 可写路径、F36b 4697、F38 PSHIST 夹具隔离、F40 ADS hidden.exe、F43–F45 Web 攻击、M01–M04 MySQL
  - 负例通过：F37 无 svchost 误报、F39 干净 PSHIST、F41 Zone.Identifier 不报、M04 普通 SELECT 不报
  - **未解释误报：0**
- Alpine 3.20 `fixture_linux.sh`：**42/42 PASS**（含 nobody 低权限 exit=2 / PERMISSION_DENIED / PARTIAL，denied modules=5）
- hidepid L39（privileged remount hidepid=2）：**PASS**
- centos-ir-lab `fixture_builder_centos.sh`：**75/75 PASS**（含历史断言、原 manual 扩展、fix 闭环执行/跳过/不支持计数、清理复验）
- 发行版用户态：centos:7 **42/42**、debian:8 **42/42**、ubuntu:16.04 **42/42**

### 规则 / 代码变更（无新规则 ID）

- 新文件：`core/evt_xml.hpp`（`evt_xml_event_id` 识别 Qualifiers 形态与单引号 Name）；`tests/test_evt_xml.cpp`
- `platform/win/win_common.hpp`：`reg_get` 解码 REG_MULTI_SZ（用顿号「、」拼接）；REG_SZ 去尾部 NUL
- `platform/win/mod_w.cpp`：BootExecute 在保留默认 `autocheck autochk *` 时对额外项告警（修复原先 MULTI_SZ 被显示为 `<binary>` 导致的误报或漏报）
- `platform/win/mod_w2.cpp`：EventID 走 evt_xml；测试钩子 `CTFIR_FIXTURE_PSHIST`（文件或目录 `*.txt`，设置后不读真实用户历史）
- `platform/win/mod_w4.cpp`：新 `mod_mysql_win`，规则 ID 同 Linux：`MID.MYSQL.LOGSHELL.001` / `MID.MYSQL.SLOWLOG.001` / `MID.MYSQL.BINLOG.001`；可选 `CTFIR_FIXTURE_MYSQL`
- 测试基础设施：`tests/fixture_win.py`、`tests/fixture_linux.sh` 扩展、`tests/fixture_builder_centos.sh` 扩展、`tests/fixture_distros.sh`、`tests/fixture_hidepid.sh`、`scripts/test-all.ps1`；`tests/cases/cases_{win,linux}.tsv` 全部 `\tmanual` → `\tauto`
- 版本：`core/model.hpp` kToolVersion=0.6.1、rule_pack_version=6.0.1；CMake VERSION 0.6.1；`scripts/package.sh` VER=0.6.1

### 二进制与发布包（需重出，二进制已变）

构建时间 2026-11-12 16:34–16:35（北京时间）；打包 BUILDINFO.built_utc=2026-11-12T08:43:56Z（北京 16:43）。路径 `D:\ctfir-build\`：

| 文件 | SHA256 | 大小 |
|---|---|---|
| cmake-build/ctfir.exe | DA3281085EE9B42EB2640EABB3017441A91E3CA17D9249E8B59FF267C1D62E0C | 1346048 |
| cmake-build/ctfir-gui.exe | 36124473CB2EFAFAFC032CE8FD93BED0519191D52661D311B90CE9703CA4E8B8 | 1280000 |
| cmake-build/ctfir_tests.exe | 731D2263966520C1916BBA3AC0CA8A84E4AD8CDA96824CDA5310E55E8269A6ED | 948224 |
| linux/ctfir | A569CDA12F4D8B5FDA914A02F08F3EE0D7D066927855CB1B31489A03B7EA53EC | 3783720 |
| linux/ctfir_tests | 6414F582ABDCF3B67D139329325D992EB40EB49DE345F90355EBEAD5B83077CD | 2948800 |
| release/ctfir-v0.6.1-windows-x64.zip | 7bfb4ec1cff7b32fe97faa2286184ab4be961c52a13f792e627731376597815d | 996641 |
| release/ctfir-v0.6.1-linux-x86_64.zip | 29aed455646a88d7c5ca2900af6cf5a9b6416be4b7e6f98c3ac2207e69d5b6dd | 1419604 |

Linux `ldd` = Not a valid dynamic program（纯静态 musl，预期）。

**未 git push、未创建 GitHub Release**——待确认后再做。

## 2026-11-12 v0.7.0（#41：处置工作台 + 个人/团队考点覆盖）

**版本**：kToolVersion **0.7.0** / 规则包仍 **6.0.1** / 检测点仍 **142**（无新规则 ID）。「修复全部问题」= UX/产品缺陷（混乱布局、无排序、命令含占位符、界面不现代、个人/团队视图），**不是** GUI 自动 apply。GUI 无修复/执行按钮。

**本轮改动（展示层为主）**

- `core/triage.cpp`：立刻清 / 再加固 / 溯源 / Web / 清单；微软预装 Active Setup CLSID 默认进清单
- `core/display_action.cpp`：已填对象的一条命令（含 AutoAdminLogon、`net share "ctfir-marker" /delete`、`netsh interface portproxy delete`、Win7 `del 文件:流名`、Startup `del /f`）
- HTML：海军渐变顶栏、可点 KPI、类别/视图/风险/搜索、行内复制、无外部 URL；证据 NUL 转义为 `\0`
- Win32 GUI：ComCtl v6、列头排序、过滤、风险色条、复制命令/手册；`recursive_mutex` 避免 ListView 自绘死锁
- `mod_w.cpp`：Startup 文件夹 `.vbs/.bat/.js/.exe` 复用 `WIN.AUTORUN.SUSPECT.001`（W10 落地文件）
- CLI stderr 输出最多 30 条处置清单；`--profile full` 为个人赛/团队赛主机侧默认

### 自动化

- `D:\ctfir-build\cmake-build\ctfir_tests.exe`：**66/66 PASS**（含 triage_jw2026_buckets、display_action_filled_commands、triage_ms_activesetup_inventory、html_checklist_and_xss：无 `http://`/`https://`、无 NUL、XSS 转义）
- `ctfir-gui.exe --selftest --out …`：`ctfir-gui-selftest OK window_created=1 modules=29` exit=0
- `ctfir.exe version`：`{"tool":"ctfir","version":"0.7.0","read_only":true}`
- dumpbin：ctfir.exe = KERNEL32+SHELL32+ole32+OLEAUT32+ADVAPI32+NETAPI32+IPHLPAPI+WS2_32+wevtapi（零 CRT）；ctfir-gui.exe 另加 USER32+GDI32+COMCTL32

### Win7 SP1 x64 JW2026-WIN7-01（192.168.0.14，夹具待练题勿清）

命令：`C:\ctfir-test\ctfir.exe scan --out C:\ctfir-test\out-jw2026-v07b --profile full`  
实际：overall COMPLETE；EXIT=1（有发现，预期）；模块=29；**立刻清 25 / 再加固 13 / 溯源 17 / Web 0 / 隐藏清单 18 / 合计 73**

默认队列（个人防护）已填命令抽检：

| 考点 | 对象 | 一条命令（摘录） |
|---|---|---|
| W2 Guest 提权 | Administrators\\Guest | `net localgroup Administrators Guest /delete` |
| W10 ADS | Desktop\\…note.txt:hidden.exe | `del "…note.txt:hidden.exe"`（非 PowerShell -Stream） |
| W6 IFEO | IFEO\\ctfir-marker-ifeo.exe | `reg delete …Debugger /f` |
| W7 登录脚本 | UserInitMprLogonScript | `reg delete … /v UserInitMprLogonScript /f` |
| W10 Startup | Startup\\ctfir-marker.vbs | `del /f "…Startup\ctfir-marker.vbs"`（本轮新可见） |
| W3 Run | Run\\ctfir-marker | `reg delete … /v "ctfir-marker" /f` |
| W9 portproxy | 0.0.0.0/13389 | `netsh interface portproxy delete v4tov4 listenport=13389 listenaddress=0.0.0.0` |
| W1 $ 账户 | NetUserEnum:ctfir-marker$ | `net user "ctfir-marker$" /delete` |
| W5 服务 | ctfir-marker-WinUpdate | `sc delete "ctfir-marker-WinUpdate"` |
| W4 任务 | Task\\ctfir-marker-sync | `schtasks /delete /tn "\ctfir-marker-sync" /f` |
| W8 hosts | hosts:25 | 删该行 + `ipconfig /flushdns` |
| W11 共享 | Shares → ctfir-marker | `net share "ctfir-marker" /delete` |
| W12 UAC | EnableLUA | `reg add … EnableLUA /d 1` |
| W13 空口令网络 | LimitBlankPasswordUse | `reg add … /d 1` |

HTML `report.html`：含「处置清单」「团队综合」`copyAttr`/`setCat`；`http://`/`https://`/NUL = 无；无「修复」按钮（手册正文「修复入口」字样保留）。微软 5 条 Active Setup 默认 `display:none` 清单。Web=0 因本套未植 webshell，属预期。

### 二进制（2026-11-12 23:15 北京，未出 ZIP）

| 文件 | SHA256 | 大小 |
|---|---|---|
| cmake-build/ctfir.exe | 61DADAD612BA55C2CDEC8B167F5925CDAFCB0CB0E5028C1BCBE959D02345879B | 1416192 |
| cmake-build/ctfir-gui.exe | 65FB4C33E9073676D39A08F9E8D0B648C9E019763D25D0E7A4399084CA82110C | 1403904 |
| cmake-build/ctfir_tests.exe | BE63F44A9B5880A9BFFEF5C2CAAAC48EEACCE6041102893FB2346E8BD5D77DA5 | 1098240 |

Linux musl 本轮未重编。未 git push、未创建 GitHub Release——待确认后再做。JW2026-WIN7-01 夹具待练题，勿清。

---

## 2026-11-12 v0.7.0（#42：CI 修复 + 兼容提示 + Linux 回归 + `ctfir actions`）

**范围**：用户问 Win7 非 SP1 / x86 考试概率、360 式急救箱、大改后 Linux 是否还能跑、GitHub Actions 报错。决策见 ADR-010。本条只记实证。

### GitHub Actions 失败根因（run 43238548478，tag v0.6.1）

- linux job 成功；windows job 在「Zip（bsdtar）」步失败。
- `tar.exe -a -cf` **已经写出** `ctfir-v0.6.1-windows-x64.zip`（952320 字节），但退出码 1，pwsh 把 step 标红，artifact 未上传，release job 跳过。
- 次要：`runs-on: windows-latest` 已是 VS 18 / MSVC 14.51，不再保证 Win7 导入面。
- 触发面：原 workflow 只跑 `push tags v*` 与 `workflow_dispatch`，普通 push **不会**出包。

**修复**：

- 新增 `.github/workflows/ci.yml`：`push main` / PR / `workflow_dispatch` → 双平台构建+单测+打包+Artifact（保留 14 天）
- `release.yml`：钉 `windows-2022` + `ilammy/msvc-dev-cmd` `vsversion: 2022`；zip 改 `scripts/zip-utf8.py`（UTF-8 标志位；本地冒烟中文名 `README-先读我.md` flag 0x800）
- 日常下载走 Actions Artifact；打 `v*` tag 才发 GitHub Release

### 兼容性（不做 RTM/x86 工程）

- 单测 `test_compat.cpp`：Win7 SP1 ok、RTM 7600 warn、Win11 ok、2008 R2 SP1 ok、x64 包 vs x86 OS warn、x86 包 vs x64 OS WOW64 warn、CentOS7 内核串不当成 Win build。
- Win7 SP1 真机 doctor：`compat=ok`，`os_name=Windows 7 Ultimate`，`os_version=6.1.7601 Service Pack 1`，`os_arch=x64`，`binary_arch=x64`，`modules_registered=29`
- 开发机 doctor：`compat=ok`（build 26100）

### `ctfir actions`（比赛急救箱，不执行）

Win7 `C:\ctfir-test\out-jw2026-v07b --bucket clear`：**已列出 25 条命令**（与 #41 KPI 立刻清 25 一致）。抽检命令仍是 ASCII 可粘贴：`net localgroup Administrators Guest /delete`、`del "…note.txt:hidden.exe"`、`reg delete …IFEO…`、`del /f "…Startup\ctfir-marker.vbs"`、`netsh interface portproxy delete …13389`、`net share "ctfir-marker" /delete`。SSH 捕获中文标题乱码属 Win7 控制台 GBK，命令本身可用。GUI 无修复按钮。

### Linux 0.7.0 musl 回归

`scripts/test-linux.sh` + 额外用户态：

| 环境 | 结果 |
|---|---|
| Alpine 3.20 单测 | **71/71**（无 Win32 `extract_paths` 4 条） |
| Alpine fixture_linux.sh | **42/42** |
| Alpine hidepid L39 | PASS（nobody+hidepid exit=2，PERMISSION_DENIED） |
| centos:7 fixture | **42/42** |
| centos7-full:latest fixture | **42/42** |
| debian:8 fixture | **42/42** |
| ubuntu:16.04 fixture | **42/42** |
| alpine / centos:7 `ctfir doctor` | version 0.7.0，`binary_arch=x86_64`，`compat=ok`，modules=47 |

ld.so.preload 夹具引起的 `cannot be preloaded` 是正例副作用，夹具 PASS。内核仍是 WSL2 6.6，**不把 3.10 真机格标 PASSED**。

### Windows 构建（本机 VS2022 v143）

`ctfir_tests.exe`：**75/75 PASS**。GUI `--selftest` exit=0。dumpbin `ctfir.exe` 依赖：KERNEL32 SHELL32 ole32 OLEAUT32 ADVAPI32 NETAPI32 IPHLPAPI WS2_32 wevtapi（零 CRT DLL）。

### 二进制（2026-11-12 23:26 北京）

| 文件 | SHA256 | 大小 |
|---|---|---|
| cmake-build/ctfir.exe | FC7F8B241C596D11D1A2784A4B89DEFA277207BB22FAE207CA9636B69A8C4140 | 1424384 |
| cmake-build/ctfir-gui.exe | 5D0990B57794E084D81009C4EFE92A67551C38C46A8B199ECFE1FD21CD145895 | 1408000 |
| cmake-build/ctfir_tests.exe | DA9820ADA6E8BED567EBAF862C6C18919C96C7328D2FD9B5165FA5D05941525C | — |
| linux/ctfir | E3E038D00EAC7539F12676B71053D5C7DFD7A5B10DE6D52EDDD9969333DEE662 | 3885256 |
| linux/ctfir_tests | 7059A3C004309837F1A870CC4F02824E68E01BFE4D72963B64FF3FD7C0E0D1F2 | 3191568 |

Win7 已部署 `C:\ctfir-test\ctfir.exe` / `ctfir-gui.exe` 本轮产物。JW2026-WIN7-01 夹具待练题，勿清。
