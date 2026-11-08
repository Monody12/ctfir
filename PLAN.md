# 离线 CTF 应急助手（ctfir）：全流程研发交接计划 v0.3

> 面向任意代码开发 Agent 的独立、可执行交接文档。无需阅读此前聊天或 Page 即可理解背景、约束、开发顺序和验收方法。

## 0. 文档状态、用法与总原则

- 文档版本：v0.3；v0.2 编写及资料核实日期：2026-11-08，北京时间（Asia/Shanghai）；v0.3 为开工修订，变更清单见 §18.3。
- 文档类型：研发实施规范与交接计划，不是已实现软件、测试报告或功能完成声明。
- 第一目标：从实际具备构建与测试条件的开发启动点起，争取 **48 小时内交付首个可用只读 MVP**。48 小时是目标，不是保证；没有假定具体比赛日期。
- 执行主体：开发 Agent 完成设计细化、代码、构建、测试、文档、打包与后续迭代。用户负责需求、使用验收和反馈，不承担逐步指挥编译/修依赖的职责。
- 平台无绑定：Grok build、Claude Code 或其他具备文件、编译和测试能力的 Agent 均可执行；交接依赖仓库文件，不依赖某聊天平台的记忆。
- 本文是研发需求的主文件；旧版 v0.1 的长期排期和首版修复功能范围已被本版替代。不再创建/更新 Page、Notion 或额外离线备考笔记。
- v0.3 开工记录：项目定名 `ctfir`，目录 `zcode-projects\ctfir\` 已建立并按 §11.2 台账管理（仓库内 PLAN.md 为此后主计划正本）；资源预盘点已完成（见 §12.1）；M0 兼容 PoC 按 §12.2 执行。环境探查均为只读。

### 0.1 对“可用”的定义

可复制到获授权靶机本地，在无互联网、无额外目标机运行时安装的情况下启动；提供 Windows 原生 GUI 和 CLI 兜底、Linux CLI；能完成明确范围的只读检查，解释证据与限制，输出 JSON 与自包含 HTML，以及可复制的手工复核/修复步骤。任何未实现、未读取、超时或缺权限项目都明确列出，绝不当成安全。

这不是两天内做完商业 EDR 的承诺。若兼容性或测试资源不足，只能发布“已测平台、已测规则”的预览版，同时公布未支持格；不得将交付日压力转化为虚构测试通过。

### 0.2 首版不可违反的红线

1. **只读扫描＋建议，不实现自动修复。** 没有隐藏的 `apply`、`fix`、禁用任务、删账户、改配置、杀进程、运行 SFC/DISM 修复等写动作。
2. 无远控、云端、遥测、联网信誉查询、自动下载、开机服务、自建计划任务、内核驱动或安全控制绕过。
3. 不抓取凭据，不保存 shadow 密码哈希、SAM 密码哈希、私钥或密码；合理的题目证据字段如用户名、任务命令、文件路径、IP、公钥指纹应在授权范围保留，不能一概丢掉。
4. 目标机不要求安装 VC Redistributable、.NET、Python、Node、WebView2、Qt 等运行时。构建端可以按授权准备工具，不能把这个要求转嫁到赛场。
5. 默认不触碰用户当前训练机配置。既有“5/8”进度保持原状；本轮未复核具体哪五项，不能伪造完成情况。
6. 只在合法授权范围采集；报告输出是明确允许的写入。读文件可能影响 atime，程序/提权可能产生日志，启动前说明这些不可避免副作用，不声称“零痕迹”。

## 1. 项目背景、用户故事与产品范围

### 1.1 背景

用户正在备赛并初学应急取证，训练涉及 Windows 与 Linux。离线赛可携带个人电脑、笔记和工具，但不能依赖互联网。用户发现来回切换账户、计划任务、系统完整性、进程网络等工具容易遗漏；希望通过一个入口、固定检查清单和中文解释，快速发现线索、知道为什么可疑、接下来如何核实。

环境可能包括 Win7、Server2008 R2、CentOS7 以及现代系统。Windows 多通过 RDP 操作，Linux 通过 SSH/scp 搬运工具。不能假定所有比赛固定某 OS、补丁集、网络策略或权限。自研的优势是流程可控、题型贴合和统一证据，而非天然比成熟工具更全面；实际覆盖由测试证明。

### 1.2 核心用户故事

| 编号 | 用户故事 | 可观察验收结果 |
|---|---|---|
| US01 | 我不懂复杂命令，想打开 Windows 程序后点一次只读扫描 | GUI 显示范围/权限；开始后各模块有状态；没有执行修复 |
| US02 | 我担心漏查系统用户 cron 或64位启动项 | 覆盖清单列所有声明来源、视图与漏项；非当前用户/不同位数不能静默忽略 |
| US03 | 我看到可疑项，却不知道为什么 | 详情包含原始位置、原文片段、理由、风险、置信度、误报和复核步骤 |
| US04 | 我在 CentOS7 仅有终端 | 拷入匹配二进制后 CLI 运行，不需要 Python、在线包安装或图形环境 |
| US05 | 我没有管理员权限 | 尽量继续可读模块；缺权限明确显示，不给全机安全结论 |
| US06 | 我只能离线查资料 | 内置帮助、解释、报告均不加载网络资源；建议复制出来可读 |
| US07 | 我换开发 Agent 接着做 | 新 Agent 读状态文件即可复现构建、识别未测项和继续下一任务 |
| US08 | 我想手动修复，但怕误伤 | 提供精确对象、备份/回滚说明和风险；不自动改动、不生成一键清理脚本 |

### 1.3 MUST / SHOULD / COULD

**MUST（不可为了赶两天删除）**
- 原生 Windows GUI＋CLI，Linux CLI；单入口“扫描声明范围内全部适用模块”。
- 只读安全边界、状态机、证据链、范围和权限提示、超时与取消。
- Windows 账户/组、任务、主要启动项、服务、hosts；Linux UID0/授权 keys/cron/profile/preload/hosts 的基础完整来源检查。
- 关键文件哈希采集和可信度标注；没有可信基线时只能给“待比对”，不能称文件未篡改。
- JSON 与自包含 HTML、可复制解释/建议、中文/Unicode、离线帮助。
- 固定依赖、许可证清单、真实构建/测试记录、已测平台列表、发布包 SHA256。

**SHOULD（48h尽量做，未达成须公开）**
- systemd、SSH Include/Match 有范围说明的解析；关键 ELF 包验证适配。
- Windows 文件签名/目录签名基础验证；有限进程路径及连接采集。
- 基础 SUID/SGID/caps 范围扫描、输出脱敏、只读 HTML 报告本地搜索。
- 普通权限与提升权限对照测试；RDP 搬运后本地启动验证。

**COULD（后续）**
- TUI、跨会话 diff、事件日志关联、WMI 持久化、深层 SAM 异常专项、签名规则包、离线镜像证据模式。
- 经另行批准和充分测试的可控修复/备份/回滚。首版不留可执行写动作开关。

### 1.4 首版非目标

不做全盘 AV、漏洞利用、自动破解、内存转储/镜像解析、内核级 rootkit 全覆盖、自动攻击链结论、远程管理服务、批量主机编排、自动网络隔离或安全加固。Server Core 不要求 GUI；Linux TUI 不挤占首版 CLI 预算。无基线时不能凭文件名正常、签名有效或工具自校验就认定系统可信。

## 2. 决策台账：已确认、代决策与待实证

| 类型 | 决策 | 对实施的约束 |
|---|---|---|
| 用户已确认 | 最近两天首个可用版本，Agent全程开发 | 用48h MVP和后续全景拆分，不再沿用每周人力排期 |
| 用户已确认 | 个人/队内非商业，可接受必要开源 | 仍需许可证审查；队内发包也可能是分发，不自动豁免 |
| 用户已确认 | 首版只读扫描＋可复制修复步骤 | 彻底排除自动写动作和复杂提权broker |
| 用户已确认 | Windows原生桌面，兼容老新系统，不现场补运行库 | 采用原生C++/Win32、静态CRT和干净机门禁 |
| 用户已确认 | Windows RDP、Linux scp | 手册支持合规搬运；不保证所有RDP都能传文件 |
| 本计划代决策 | 主线最低Win7SP1/Server2008R2SP1 | RTM不阻塞48h；见第3节证据和降级办法 |
| 本计划代决策 | Linux CLI首发，TUI后续 | 无TTY/管道可用；不能只做TUI |
| 本计划代决策 | C++17共享模型/规则/报告，平台后端独立 | 不绑定某Agent；禁止擅自改为Web应用 |
| 本计划代决策 | 原创代码MIT作为默认提案 | 正式公开/分发前由用户确认，不在未确认时声称已选许可证 |
| 待实证，不阻塞写代码 | 构建宿主、合法VM、管理员/root测试条件 | 先列资源台账；缺失格标未测，不造支持 |
| 待实证 | 精确MSVC/SDK/musl及库构建的最低运行条件 | 首4小时PoC冻结；官方targeting声明不等于本程序通过 |
| 待实证 | 实际赛事OS、补丁、传输与修改限制 | 用户获知后修订profile；不要求现在补答所有细节 |

Agent对低风险实现细节自行选定并记ADR；只有改变平台下限、首版只读边界、许可证/分发方式、依赖主线、数据敏感范围或必须延长交付目标时，才提交决策说明。不要把几十个细节选择丢回给初学用户。

## 3. Win7 是否可能没有 SP1：证据与兼容决策

### 3.1 本轮实际查到什么

- 微软 MS17-010 公告列出 Windows7 SP1 x86/x64、Server2008 R2 SP1 等受影响/更新版本；公告明确，未列版本可能已过支持周期，也可能不受影响。[S01]
- 因此不能据公告缺少 RTM 推断“Win7 RTM 不受影响”，也不能由 EternalBlue/MS17-010 题推断“比赛必定SP1”。SP1 与是否已安装 MS17-010 补丁是两件事。
- 一手 CTF VM 构建仓库 `gsingh93/ctf-vm-windows7` 的 README 使用 Win7 SP1，并明确可以去掉 `scripts/sp1.ps1`，不安装SP1；同时提醒有些工具要求SP1。[S02] 这是一个公开构建实例，不是所有赛事的统计。
- 检索到的青少年CTF文库 Solar 训练合集列出 Win7 日志靶场与 Server2019 场景，但不能据其未写SP版本就认定为RTM。该培训汇编只是题材/平台多样性的旁证。[S03]
- **没有获得足以统计所有赛事SP1/RTM比例的权威数据**。本文不声称“一般都有SP1”或给RTM出现概率。

### 3.2 最终决定

主线最低 Windows7 SP1（6.1 build7601）与 Server2008 R2 SP1 x64。Win7 RTM（build7600）列为能力外：启动探针若能运行，识别版本并提示“未支持/未验证，不保证扫描完整”；若主程序因运行时/API在启动前无法运行，则由使用手册给出 `winver` / `systeminfo` 人工识别步骤，不编造能在崩溃前显示友好提示。

首版不承诺独立RTM兼容引擎；可用同工具链做小型版本诊断探针，但只有测试成功才装包。拿到明确赛事RTM需求后，再评估单独legacy分支、最小API集、构建工具与专用回归，不为一个未证实需求拖垮两天目标。不能现场要求用户给靶机升级SP1、打补丁或改题。

### 3.3 官方编译支持与实际最低运行条件

- 微软当前文档说明 VS2026 18.0 起不再以 Win7/8/8.1 和 Server2008R2/2012/2012R2 为目标；主线选择 **VS2022 v143**，不是不加区分的“最新VS”。[S04]
- 首选 VS2022 17.14/v143 14.44 系列的受维护修订版；开发启动时记录精确版本。Windows SDK不能只写“最新”；由PoC锁定，改版必须重跑旧系统启动门禁。工具链支持期限参考微软FAQ，不把“目标OS已停止支持”误写为编译器保证安全。[S05]
- `/MT`静态链接CRT；所有链接模块选项一致。[S06] 动态UCRT的官方旧系统部署说明要求Win7SP1，也解释了为什么不能默认无补丁RTM能通过。[S07] 这不构成 `/MT` 在任意RTM必能跑的保证。
- `_WIN32_WINNT/WINVER=0x0601`仅控制声明，不保证导入表、第三方依赖和标准库实际兼容。[S08]
- 每个Release产物必须检查导入表、依赖、架构、subsystem和旧系统启动。新增API动态探测并fallback或明确UNSUPPORTED。不能拷贝来路不明/别机系统DLL解决缺入口点。

## 4. 开源、参考工具与知识产权边界

| 参考 | 已核实情况 | 本项目做法 |
|---|---|---|
| [GScan](https://github.com/grayddq/GScan) | 公开README列CentOS6/7、账户/cron/preload等检查；本轮前期研究未确认明确许可证，常见LICENSE路径404、根目录接口超时，不足以证明全库绝无许可。[S09] | 研究检查思路，自主实现；确认授权前不复制源码、规则或打包。不是“有GitHub所以可改可发” |
| [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) | 免费使用的Sysinternals专有工具；不是开源。EULA限制发布供他人复制/转让等。[S10] | 不将二进制内置自研包；不用它作必需采集引擎，自写公开API采集 |
| [Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) | 同属专有免费工具；当前页面最低Windows11/Server2019，不能直接当Win7依赖。[S11] | 用原生签名API，输出限制；用户自行另备工具不代表许可本项目打包 |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | 仓库LICENSE为GNU AGPLv3，属于真正开源；官方有离线采集模式。[S12] | 首版不融合其源码；后续独立集成需审组合、对应源码与分发义务，不擅自声称MIT覆盖整个组合 |
| SFC/DISM | Windows自带系统组件，不是本项目可任意复制修改的开源库 | 首版不执行；建议中按OS条件说明；不给发行包塞系统组件 |

### 4.1 许可证实施要求

- 非商业与个人使用不是许可证豁免；向队友交付二进制也应核查对应分发义务。
- 原创代码MIT是提案，不是已经取得用户许可的最终发布决定。对外发布前记录批准；未批准不得借用别人的版权或虚构许可。
- GPL通常在分发被覆盖程序/衍生作品时要求依条款提供对应源码、声明等；独立聚合不自动使所有旁边代码受GPL覆盖。
- AGPL除分发外，对修改后程序还有向通过网络交互用户提供对应源码等条件；不是“任何联网软件都必须全部开源”。
- LGPLv3允许一定条件下的自选应用许可，但需要通知、库源码、重链接/替换修改库的能力等；静态链接通常需可重链接应用目标代码等合规材料，适用时有安装信息。不是静态必公开全部应用源码，也不是动态无需义务。[S13]
- 第三方库、编译器运行库、规则、图标/字体、包数据库适配代码分别登记；禁止拷贝未知授权规则。musl官方为MIT；C++运行库另审，libstdc++若使用需核Runtime Library Exception适用条件。
- 建立 `DEPENDENCIES.lock.json`、`THIRD_PARTY_NOTICES.md`、`licenses/`；每项名称、版本、上游URL、内容SHA256、许可证、使用方式、是否修改、分发材料齐备。
- 以上是工程合规约束，不是法律保证。第三方目录中保留原声明，不能统一改成自己的MIT。

## 5. 技术栈、构建与目录结构

### 5.1 首选实现

| 层 | 定案 | 必须落实 |
|---|---|---|
| 语言 | C++17 | RAII、边界检查、不可变证据模型；不使用目标新OS才有的库特性而无回退 |
| 构建 | CMake 3.28系列受控版本作为起始候选，精确patch由M0验证后锁定 | 构建宿主运行CMake，不要求目标机运行；不使用浮动latest；CMP0091 NEW与MSVC_RUNTIME_LIBRARY静态配置核实 [S14] |
| Windows | Win32 Unicode常规控件、manifest、Release /MT、v143 | ListView/TreeView/Edit/Tab等；无WebView/Electron/浏览器引擎/现场.NET |
| Linux | 静态musl C++，x86_64通用指令基线；v0.3 定案：Alpine 容器 `apk add g++ musl-dev` 静态编译，免专用交叉链 | 不用 `-march=native`；readelf检查解释器/动态依赖；CentOS7 用户态用 centos-ir-lab 容器验收，内核3.10真机格另行实测 |
| JSON | nlohmann/json v3.11.3作为固定候选，MIT全文已核实 [S15] | 开工做安全公告/编译核查；审核通过后锁源哈希。若有安全问题提升级决策，不盲目锁旧版或跳最新 |
| 哈希 | Win BCrypt SHA256；Linux使用经审查固定版本实现 | 不自创密码算法。Linux候选库必须先核授权/静态构建，首4h定案并记录；不可调用被替换sha256sum自证可信 |
| 报告 | UTF-8 JSON＋无外部依赖HTML | 转义不可信文本；首版可无JS，以浏览器Ctrl+F查询，禁止任何网络资源 |
| 规则 | 编译期原创规则＋受限JSON元数据 | v0不允许任意shell/Python插件，不支持未经签名/核验的外部规则包热加载 |

依赖获取只发生于开发环境，经许可/安全检查与hash核对后存入构建缓存；重复构建不需要在线解析浮动版本。构建机器可安装编译器/交叉工具链；目标机绝不安装。若Agent环境只有Linux，不能用“交叉编译出了EXE”冒充Win7实测；必须找到已授权Windows构建/运行宿主或如实标阻塞。

### 5.2 为什么不换到看似更快的栈

- Qt6官方当前平台表不支持Win7。[S16] Qt5.15历史表支持Win7的部分组合，但具体补丁/维护/静态许可需审核，首版不引入新变量。
- Go1.21起要求Windows10/Server2016；为Win7冻结Go1.20将承担过时依赖风险，不作主线。[S17]
- Electron/WebView2/.NET/Python GUI都有版本/运行时/旧系统问题；不能以“自包含”三个字代替最低OS实测。
- 不同时开发Rust/Go第二套核心；若以后换栈，必须ADR与兼容性证据，不在48h中途重写。

### 5.3 静态链接并非万能

Windows仍用系统DLL、COM、签名链与OS组件；目标是“不需再安装运行时”，不是物理上零DLL。第三方库必须同CRT选项静态构建，导入新API必须处理失败；延迟加载只是避免启动即失败，不是功能已兼容。

Linux静态musl降低glibc依赖，但不解决内核syscall、CPU、权限、namespace、SELinux、包数据库、NSS/PAM/域账户语义、文件系统与外部程序版本差异。musl官方建议C++用专用工具链，不是简单musl-gcc包裹全部库。[S18] 本地账户文件不等于企业NSS目录全体用户；首版不认证密码，不调用PAM登录，不做DNS。缺rpm/dpkg或适配器不认识版本，返回UNSUPPORTED/ERROR，不返回PASS。

### 5.4 工程目录（开发Agent创建，不代表当前已创建）

```text
AGENTS.md                 # 不变约束、执行协议与授权边界
PLAN.md                   # 本文或仓库内正式主计划
STATUS.md                 # 当前阶段/构建/阻塞/精确下一步
TASKS.md                  # Issue式任务、依赖、状态、证据链接
DECISIONS.md               # ADR编号、理由、替代、影响
COVERAGE.md                # OS×模块×权限×来源覆盖台账
TEST_RESULTS.md            # 环境、命令、结果与产物hash索引
DEPENDENCIES.lock.json
THIRD_PARTY_NOTICES.md
CMakeLists.txt
cmake/toolchains/          # win32/win64/linux-musl，固定版本
apps/win-gui/  apps/cli/
core/model/ core/session/ core/rules/ core/report/
platform/windows/ platform/linux/
schemas/ rules/ tests/unit/ tests/fixtures/ tests/integration/
docs/compatibility/ docs/deployment/ docs/threat-model/
packaging/ licenses/
```

真实用户扫描结果、密码、私钥、SAM/shadow内容不进git；测试夹具与用户证据分离。后续TUI/修复目录在批准对应阶段后再建，首版不藏未公开执行器。

## 6. 兼容与覆盖矩阵：收缩但不伪造

### 6.1 首版设计目标

| 优先 | 平台 | 验收格与限制 |
|---|---|---|
| P0关键 | Win7 SP1 x64（v0.3：x86 自本行降入 P1） | 原生x64包，干净SP1与补丁/签名基线分开；不用x86采集静默漏64位视图 |
| P0关键 | Server2008 R2 SP1 x64 | 桌面安装可GUI；Core只CLI；不列不存在的普通x86目标 |
| P0代表 | Win10 22H2 x64、Win11 24H2 x64 | 固定代表版测试，不能外推所有Win10/11构建 |
| P0关键 | CentOS7.9 x86_64 | kernel3.10/glibc2.17代表基线；实际包/镜像记录；不要求靶机编译 |
| P1首版尽力 | Win7 SP1 x86、Ubuntu22.04/24.04、Debian12 x86_64 | x86构建配置保留、首版不打包不测试；其余先验证静态启动和基础文件采集；包数据库/日志适配分项标记 |
| P1后续 | Server2016/2019/2022/2025、更新Win11；Rocky8/9、Debian13、Ubuntu26.04 | 逐格补VM回归，不因API相似直接宣称支持 |
| 能力外 | Win7RTM/2008R2RTM、XP、Vista、IA64、ARM64/aarch64 | 版本提示/探针尽力；实际需求确认后另支线 |
| 特殊受限 | 容器、WSL、OpenRC/Alpine、只读镜像 | 明确init/namespace/宿主不可见限制；无systemd不算systemd扫过 |

P0表示优先设计与验收目标，不等于48h必定全通过。无合法镜像/实机时该格状态必须 `NOT_TESTED`；已构建但未运行写 `BUILT_NOT_RUN`。发布只能说“支持列表中已测格”，未测P0仍是剩余工作，不改成通过。

### 6.2 兼容台账最小列

OS版本/build/SP、架构、补丁集、locale、文件系统、权限、运行方式（控制台/RDP/SSH）、runtime基线、工具版本与hash、规则版本、doctor/scan/report结果、测试证据位置、已知限制、结论和测试时间。时间保存原始区与偏差，报告展示北京时间。

旧系统签名分开测试：A＝干净SP1无额外运行库；B＝SHA-2/服务栈和信任根基线。KB4474419/KB4490628参考微软旧系统SHA-2更新说明，但不能保证所有代码签名链离线有效。[S19] 缺链、吊销未知、错误系统时间分别显示；不自动更新根证书/打补丁。签名有效不代表程序良性。

## 7. 架构与安全边界（首版无修复执行器）

```text
Windows GUI ─┐
Windows CLI ─┼─> Session / Scope / Scheduler
Linux CLI ───┘          |
                 Native Collectors
                        |
       Immutable Evidence + normalized objects
                        |
       Original Rules -> Findings + Limits
                        |
      Explanation + Manual Advice (text only)
                        |
          JSON / self-contained HTML / logs
```

- core只认识通用对象与错误；平台句柄封装在后端，不在UI与规则里散落OS调用。
- GUI与CLI复用同一profile、规则和结果，避免检测范围两套。
- collector只采证，rule只评估，advice只生成文本。首版没有planner到executor的可执行路径。
- 默认普通权限；用户显式“以管理员重新启动只读扫描”可由UAC启动完整只读进程/worker。拒绝UAC继续受限扫描，不绕过控制、不安装broker服务。
- Linux由用户显式sudo运行，不装setuid、不给sudoers添加规则、不改PAM。
- 不自动加载离线用户hive，不source脚本，不执行命中EXE/任务，不加载可疑库，不渲染外部对象。
- 外部命令只在不可避免的包验证等适配器中使用：绝对路径、类型化固定参数、不经shell、清理影响解释的环境变量、记录hash/version/返回码/stderr/超时；不得相信PATH/alias或被替换ps。
- 每模块可失败，其他模块继续；COM/WMI/外部命令用隔离worker控制超时。取消只结束自家worker，绝不杀目标进程。
- 遍历不默认跨挂载点/远程共享，不无限递归，不跟随未知软链接/junction，按文件数/字节/时间预算停止并记录SKIPPED。

## 8. MVP规则与采集目录

### 8.1 范围标记和统一输出

- **A / P0完整来源基础检查**：首版必须覆盖表列来源、权限/错误路径，并实现少量可解释规则；“完整”指已声明来源，不是该领域所有攻击技巧。
- **B / P0基础采集、SHOULD规则**：首版尽量采齐基础字段，深度评估后置；字段缺失不能装成已判断安全。
- **C / P1后续**：不计入已实现能力；UI列“未支持专题”，不隐藏。
- 每个模块产出：采集范围、Evidence、检查状态、Finding、原始错误、限制、复核和建议。每条已发布规则最低1正例＋2负例＋1权限/故障例。
- 表中修复均为**文本建议**。严禁扫描时执行。

### 8.2 Windows

| 模块 /优先 | 来源/API与输出 | 判定与误报边界 | 权限/失败 | 最低测试与建议 |
|---|---|---|---|---|
| W01账户/管理员组 A | NetUserEnum/NetUserGetInfo、NetLocalGroupGetMembers；按SID识别本地管理员组而非英文名称；SID/RID、禁用状态、组关系 | 新增/额外管理员、异常权限组合；账户以`$`结尾不是恶意充分条件；改名内置账户不能靠名字识别 | 域控制器与域账户不等同本地SAM；访问拒绝说明范围 | 正：测试额外管理员；负：改名Administrator、授权运维账户；fault：权限拒绝。建议核授权/日志，非自动删 |
| W02登录界面隐藏 A | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`；与W01对照，列值类型/数据 | UI隐藏≠底层SAM隐藏；合法服务账户可隐藏 | 键不存在可完成无该配置；读拒绝不同于不存在 | 正：夹具隐藏标记；负：无键/正常可见账户；fault：拒绝。建议保留原值后人工确认 |
| W03任务 A | Task Scheduler COM 递归目录，含隐藏任务查询；XML、动作、触发器、主体、启用状态、任务路径 | 临时/可写路径、异常参数与权限组合；备份/安装任务可能相同 | COM未启动、损坏XML、子目录拒绝逐项计数，不能只扫根文件夹 | 正：无害marker任务；负：系统任务/合法备份；fault：服务不可用。导出XML建议、不要禁用 |
| W04服务 A | SCM枚举/QueryServiceConfig，启动类型、账号、ImagePath、依赖；驱动先基础条目 | 可写路径/异常参数/非基线服务；第三方服务正常，不默认全报警 | 不要求停止/启动服务；部分配置拒绝返回受限 | 正：测试服务配置夹具；负：微软/合法第三方；fault：拒绝。确认后人工处置说明 |
| W05主要自启动 A | HKLM与当前/已加载用户HKU的Run/RunOnce，Winlogon Shell/Userinit，IFEO Debugger，用户/公共Startup；AppInit_DLLs、Winlogon\Notify、LSA Authentication Packages/Security Providers、Print Processors（v0.3补）；x64双注册表视图 | 指向可写目录、非预期debugger等；调试/运维工具会误报 | 未加载用户hive明确未覆盖，不自动加载；系统目录重定向说明 | 正：无害启动项；负：合法厂商/调试项；fault：用户hive不可读。显示精确值，不删整键 |
| W06 hosts A | `%SystemRoot%\System32\drivers\etc\hosts`，原始行、映射、元数据/hash | 与显式题面/可信基线差异；无基线不能判所有内网映射恶意 | 文件不存在/拒绝/非法编码分开 | 正：异常测试域映射；负：localhost/合法内网；fault：拒绝。建议备份后逐行核对 |
| W07进程/连接 B | Toolhelp/PSAPI/QueryFullProcessImageName；IP Helper TCP/UDP owner表；PID+创建时间身份、路径、父子信息可得部分 | 路径、签名、监听组合；端口号不单独判恶意；瞬逝/保护进程不能判隐藏；v0.3补挖矿特征（stratum+tcp、矿池域名、kdevtmpfsi/kinsing等进程/命令行） | protected process、位数、权限受限显示字段unknown | 正：测试进程路径；负：正常服务/瞬逝；fault：拒绝。只读复核、不kill |
| W08关键文件哈希/签名 B | OS匹配列表如系统目录cmd、tasklist、sethc/utilman/osk/Magnify/Narrator（v0.3补粘滞键后门核对）等；BCrypt SHA256、WinVerifyTrust/目录签名可用范围；嵌入/目录/链/吊销分别记录 | 无签名≠恶意；有签名≠安全；同版补丁基线才可比对 | 离线cache-only，不发HTTP；缺链unknown；catalog不支持时不得说无签名 | 正：测试副本字节变更；负：合法不同补丁/离线缺链；fault：拒绝。建议可信源复核，不SFC修复 |
| W09基础事件日志 B可裁 | Event Log API有限通道/时间窗口、记录ID、原始时区 | 4624/4625登录成功/失败Top来源IP（v0.3补首规则）、账户/任务/服务线索，不自动还原完整攻击链 | 各系统通道不同，日志缺失≠无事件 | 正：合成事件夹具；负：正常登录/轮转；fault：拒绝。保存线索，不清日志 |
| W10 WMI持久化 C | 过滤器/消费者/绑定只读关联 | 企业监控也合法 | 超时/服务缺失 | 后续独立模块，不在MVP伪称覆盖 |
| W11深层SAM/RID异常 C | 多源映射/离线元数据研究 | 不等于W02，不能保证公开API看见一切 | 不绕ACL、不抓密码hash | 后续可信离线模式评审 |
| W12 DNS/防火墙/RDP/关键策略 C | 本地配置/适配器API，域策略边界 | 非默认配置不必恶意 | 不主动联网，不改策略 | 后续增强，不为赶期自动硬化 |
| W13 Web/日志 A（v0.3新增） | web根定位（IIS inetpub、phpstudy/xampp常见路径）、wwwroot下.php/.asp/.aspx/.jsp静态特征（eval/assert/base64_decode链、Execute Request、Runtime.exec）；IIS/Apache/Nginx日志POST Top IP、404扫描、sqlmap UA | 特征命中≠定罪，需人工复核；合法框架文件可能命中，白名单按hash+路径 | 目录过大限预算SKIPPED；日志轮转分卷逐个计 | 正：无害marker特征文件；负：正常业务php/正常访问日志；fault：目录拒绝。只读，不删webshell |

Windows XML解析如用系统MSXML需动态探测已安装版本并禁用DTD/外部实体，不能要求现场装库；首版可直接保存COM返回XML并使用COM对象读取所需字段，避免引入未验证XML依赖。命令行路径解析不得用简单按空格切分造成带引号/环境变量误判；保留原文与“解析不确定”状态。

### 8.3 Linux

| 模块 /优先 | 路径/API与输出 | 判定与误报边界 | 权限/失败 | 最低测试与建议 |
|---|---|---|---|---|
| L01本地账户/组 A | `/etc/passwd`、group、sudoers及Include（可读部分）；名称/UID/GID/shell/权限；shadow仅文件权限/owner等元数据 | 非root名称UID0、重复UID、额外特权关系；授权运维可合法 | 只覆盖本地文件，NSS/域用户不全；不导出shadow hash | 正：隔离夹具非root UID0；负：root/授权重复UID；fault：拒绝。解释不自动userdel |
| L02 SSH A | 各本地用户`.ssh/authorized_keys`、sshd_config/sshd_config.d与Include，公钥指纹/选项/文件权限 | 陌生key、危险权限、forced command等需结合上下文；公钥存在正常 | Match/Include无法完整求值明确提示；定制AuthorizedKeysFile/Command使默认路径不全 | 正：测试陌生key；负：授权key/合法限制选项；fault：用户目录拒绝。不采私钥，不改sshd |
| L03 cron A | `/etc/crontab`、`/etc/cron.d`、daily/hourly/weekly/monthly、用户`/var/spool/cron`及发行版spool、anacron | 临时可写路径/异常解释器组合；备份/运维可能相同 | 不能只查当前用户；子目录不可读计受限；不同格式留原文 | 正：marker任务；负：备份/系统维护；fault：spool拒绝。建议保存任务和引用脚本 |
| L04 shell持久化 A | `/etc/profile`、profile.d、bashrc/bash.bashrc；用户.profile/.bash_profile/.bashrc等，行号/raw/hash | PROMPT_COMMAND、alias/函数包装、异常命令组合；合法定制会命中 | 不source、不运行shell来“解析”；动态拼接无法求值就说明 | 正：无害异常标记片段；负：正常PATH/alias；fault：编码/读取失败。不给整文件删除建议 |
| L05 preload A | `/etc/ld.so.preload`、可见进程环境中的LD_PRELOAD/LD_LIBRARY_PATH、maps（限可读） | 未知库/可写路径/运行态对应；监控调试库可能正常 | 不遍历/保存完整环境中凭据；只取相关白名单字段；静态工具非内核防护 | 正：配置夹具库名；负：无配置/授权监控；fault：maps拒绝。不加载/删除库 |
| L06 hosts A | `/etc/hosts`原始行、元数据/hash | 与显式基线/题面比较；不靠IP私有/公网分类定恶意 | 编码、拒绝、缺失区分 | 正：测试异常映射；负：localhost/合法内网；fault：拒绝。手动逐行核实 |
| L07 systemd/启动 B | system/user unit目录、drop-in、wants、timers、ExecStart；rc.local/init.d/inittab基础枚举 | 意外ExecStart、可写路径/覆盖关系；自建服务正常 | 未读取运行态不称enabled已确认；无systemd不适用，OpenRC未支持单列 | 正：marker unit；负：正常unit/drop-in；fault：用户unit拒绝。不systemctl disable |
| L08关键ELF/包验证 B | ps/ss/ssh等实际路径、inode/hash/ELF基本信息；rpm/dpkg只读适配 | 同版可信包/哈希差异；本机DB可被改，配置/升级差异可正常 | 固定程序路径/hash与超时；rpm `--noscripts`适配；缺命令/坏DB不是PASS | 正：测试副本变更；负：正常升级/配置变更；fault：坏DB。异常ps不直接删，先可信同版包复核 |
| L09进程/网络 B | `/proc` PID/stat/exe/cmdline/maps/fd限量、`/proc/net` socket inode关联；必要sysfs | deleted exe、视图差异、异常路径；挖矿特征（stratum+tcp、矿池域名、kdevtmpfsi/kinsing等，v0.3补）；升级旧binary和短进程可能正常 | PID复用重采样、hidepid/namespace限制明确；不相信ps单源 | 正：无害deleted测试程序；负：升级/瞬逝；fault：proc拒绝。不能保证所有隐藏进程 |
| L10特权文件 B | 限定目录SUID/SGID、`security.capability`xattr、owner/group/可写链 | 非基线特权、危险权限链；sudo/ping等合法 | 不跨挂载/不全盘，caps解析/FS支持失败单列 | 正：夹具特权位；负：授权工具/无caps；fault：xattr拒绝。不全局chmod |
| L11日志 B可裁 | secure/auth.log、journal可用适配、wtmp等限定大小和时间 | 异常登录与时间关联，缺失只是线索 | 轮转/时区/版本/权限限制 | 正：合成登录；负：正常登录/轮转；fault：坏记录。不清日志 |
| L12网络策略/其他 C | resolv.conf、nft/iptables、at、OpenRC等 | 非默认非恶意 | 未支持列明 | 后续，不加任务、不改防火墙 |
| L13 痕迹/内核模块 B（v0.3新增） | ~/.bash_history等历史文件（行号/原文/hash）、/proc/modules或lsmod枚举、last/wtmp基础读取 | 历史是线索非结论；内核模块对照发行版基线，无基线只列证据 | hidepid/权限不足单列；history不存在≠未操作 | 正：marker历史条目；负：正常history/发行版标准模块；fault：拒绝。只读 |

### 8.4 八考点验收映射

| 用户练过考点 | 首版目标 | 边界 |
|---|---|---|
| uid0 | L01 A | 本地文件账户范围 |
| sshkey | L02 A | 定制路径/命令无法求值时显示不完整 |
| hosts | L06/W06 A | 无基线仅列证据，不武断定性 |
| cron | L03 A | 系统和全部可读用户来源 |
| preload | L05 A | 不保证内核层隐藏检出 |
| profile | L04 A | 静态解析，不执行文件 |
| replacedps | L08 B | hash与可信基线/包可用性分开；不依赖ps自检 |
| hiddenprocess | L09 B线索 | 重采样、多视图、低可信提示，不保证专项全覆盖 |

“5/8”既有状态不变，具体已完成项未知。研发在全新隔离VM/夹具中做，不重置或清理用户当前计分环境。

### 8.5 规则分级与拒绝过度结论

规则ID示例：`LNX.ACC.UID0.001`、`LNX.PERSIST.CRON.001`、`WIN.ACC.LOGIN_HIDE.001`。ID稳定不复用，内容变更有rule_version。severity（影响）与confidence（推断把握）分离，另有evidence_trust（可信度）。非root UID0可high风险但仍需人工授权核实；没签名只能线索，不能写“木马已发现”。

白名单按hash＋路径＋签名/上下文＋理由＋有效期，不按“System32全部可信”“/usr/bin不查”。首版可仅支持报告层已知项标注，不能为了做白名单跳过采证。匹配结果可查看，哈希变化即失效。

## 9. 数据契约、状态机和报告

### 9.1 实体（JSON Schema为实现必需）

| 实体 | 最小字段 |
|---|---|
| ScanSession | schema_version、session_id、tool_build/hash、rule_pack_version、host_fingerprint、OS/build/SP/arch、privilege、scope、start/end、source_timezone、module_results、overall_status |
| ModuleResult | module_id/version、applicable、planned_sources、checked_sources、omitted_sources、status、errors、elapsed、budget、evidence_ids、finding_ids |
| Evidence | evidence_id、collector/version、source_kind/path/API、capture_time、raw_ref/hash、object_identity、access_status、trust、redaction、limitations |
| Finding | finding_id、rule_id/version、platform、object_ref、evidence_ids/paths、rationale、severity、confidence、status、limitations、advice_id |
| Advice | advice_id、preconditions、manual_verify_steps、preserve_steps、backup_steps、manual_remediation_steps、rollback_notes、hazard、never_auto_execute=true |

对象身份：Windows尽可能文件ID/volume/SID/PID+创建时间；Linuxdevice/inode/UID/PID+starttime；路径是显示用身份的一部分而非永远唯一。原始证据不可变，归一化另存；hash证明采集后变化检测，不证明采集时系统诚实。

所有展示时间标北京时间；原始timestamp/offset保留，目标时钟可能偏差，不假装时间线绝对准确。会话标识随机唯一，不使用用户名+时间拼出的可猜私有目录。UTF-8为内部标准，无法解码原始路径/字节提供转义和原始引用。

### 9.2 模块状态

| 状态 | 含义 |
|---|---|
| PASS | 在声明的适用范围、证据条件下完成且未命中；不是整机干净 |
| FINDING | 完成并有待关注结果；不是恶意定论 |
| PERMISSION_DENIED | 必要来源不可读，显示具体缺口 |
| UNSUPPORTED | 组件不适用或实现不支持；reason区分 `not_applicable` 与 `capability_missing` |
| TIMEOUT | 预算到期，保留已采部分 |
| ERROR | API/解析/I/O失败，保留错误码 |
| SKIPPED | 用户排除、取消、依赖失败、预算策略，写明原因 |

执行内部可有PENDING/RUNNING/CANCELLING，最终必须落入上述终态。会话状态COMPLETE/PARTIAL/CANCELLED/FAILED；出现适用模块受限不允许会话“全部通过”。一个模块有finding且部分来源失败，用主要status表失败并保留finding_ids，而非二选一丢证据。

### 9.3 覆盖率、去重、版本

- 完成覆盖率＝完整完成的适用检查数÷本profile承诺的适用检查数。权限不足仍在分母；不能隐藏失败项提高百分比。
- 首版没有实现的专题不冒充已适用/已检查，另列“未支持专题”。范围排除、正常不适用、未实现、读取失败四者分开。
- 检测召回率不等于覆盖率；样本TP/FP/FN单独统计。
- 去重key＝规则ID＋对象身份＋证据指纹，不能仅按路径吞掉变化。
- schema major不兼容时拒绝读取并解释；minor迁移保留原会话副本。首版固定v1，不急做多代迁移引擎，但测试未知schema版本拒绝。

### 9.4 示例（仅格式示例，不是实际扫描结果）

```json
{
  "schema_version": 1,
  "finding_id": "example-finding-001",
  "rule_id": "LNX.ACC.UID0.001",
  "rule_version": "1.0.0",
  "platform": "linux",
  "evidence_ids": ["example-evidence-001"],
  "evidence_paths": ["/etc/passwd"],
  "rationale": "发现非root名称且UID为0的本地账户，需要核实授权",
  "severity": "high",
  "confidence": "medium",
  "evidence_trust": "live_local",
  "status": "FINDING",
  "limitations": ["仅本地文件账户；不能证明内核未被控制"],
  "advice_id": "ADVICE.ACC.REVIEW.001"
}
```

### 9.5 修复建议模板（只生成文本）

每条建议必须包含：
1. **先解释**：当前发现是什么，为什么可能正常，缺少什么证据。
2. **先留证**：原始配置/元数据/hash、任务XML或相关日志，提醒题目可能要求保持原状。
3. **手动复核**：只读命令/GUI路径，说明参数、所需权限与输出含义。
4. **备份前置**：保存内容与owner/ACL/xattr等；不要只复制文本就宣称完整备份。
5. **人工处置步骤**：针对精确对象、优先停用而非删除、风险与重启/失联影响；提供路径/对象占位符，须用户替换核实。
6. **回滚说明**：恢复哪些字段和状态，何时停止并请求人工恢复。
7. **复查**：再次只读扫描确认变化；修完一个项不代表系统重新可信。

禁止输出“复制即批量清理”的shell/PowerShell脚本。可以展示非执行示意如 `schtasks /Query /TN "<已核实任务路径>" /XML`、`stat -- "<已核实文件路径>"`，占位符不能自动替换执行；实际写操作优先文字步骤＋精确影响说明，不给连串清空命令。UI只提供“复制建议”，无“运行建议”。若自动引用命令中的恶意内容，必须安全转义或不生成可执行命令，避免复制注入。

### 9.6 结果目录

```text
session-<id>/
  session.json
  module-results.json
  findings.json
  advice.json
  events.jsonl
  report.html
  integrity.sha256
  evidence/             # 授权范围原始证据，私有权限
  diagnostics/          # 无凭据的错误/版本/预算记录
```

首版输出目录只由用户指定或选择明确私有目录；无空间/不可写提前失败，不偷偷写公共目录。JSONL增量落盘，完成后原子替换汇总文件，崩溃/取消后可恢复部分报告。HTML默认脱敏展示，原证据受ACL保护；用户名/IP/路径可在用户明确本地使用场景保留，导外报告可选脱敏。HTML所有不可信字段转义，禁止外部JS/CSS/图片、XML外部实体与可执行超链接；无自动上传。

## 10. Windows GUI与Linux CLI详细交互

### 10.1 Windows文字线框

```text
标题：CTF只读应急助手  版本/已测范围
顶部：主机 OS/SP/架构 | 当前权限 | 离线 | 仅只读
侧栏：总览 / 扫描范围 / 结果 / 未完成检查 / 证据 / 日志 / 帮助
总览：
  [选择输出目录] [开始只读扫描] [取消]
  适用N项 | 完成M项 | 有线索K项 | 受限/失败J项
  模块列表：名称、范围、状态、完成来源、耗时、限制
结果：
  搜索框 | 风险/置信度/模块/状态过滤
  规则ID | 对象 | 简短理由 | 风险 | 置信度
详情：
  原始证据/来源/hash → 原因/误报 → 复核 → 手动建议
底部：[复制建议] [保存报告] [打开本地报告目录]
```

- GUI打开即可看环境诊断，输出目录显式选择；范围默认CTF只读profile，不默认全盘。
- 扫描按钮不是修复。开始前简述atime/日志/报告写入影响；未管理员提醒“部分来源不可读”，允许继续。
- 用户可显式选择UAC提升重新只读扫描；首版不做复杂跨权限写broker，完整提升进程仍没有修改配置功能。
- 后台线程/worker扫描，UI消息循环不能阻塞。模块状态是真实计数，不给假进度；取消保留完成部分。
- 证据显示原文但不执行文件；双击不运行可疑程序，不自动打开网络URL。
- 1024×768/RDP、100/125/150/200%DPI、键盘Tab/Enter、中文用户名/路径、长路径尽力测试。旧新DPI API动态探测，缺API不崩。
- x64包读取正确system目录与双注册表视图；不能靠x86程序默认重定向覆盖全部64位配置。
- 缺入口点可能发生在main之前：随包提供文本诊断手册、版本与hash，不承诺GUI一定能显示所有启动错误。

### 10.2 CLI接口（设计，尚未实现）

```text
ctfir --help
ctfir doctor --format json
ctfir scan --profile ctf --read-only --out <LOCAL_DIR> --format json
ctfir explain --session <SESSION_DIR> --finding <FINDING_ID>
ctfir report --session <SESSION_DIR> --format html --redact
ctfir version
```

上述接口是开发合同而非当前可用命令；Windows使用`ctfir.exe`，Linux使用`./ctfir`。首版不接受 `apply` / `fix`；遇到明确报“只读版本不支持修改”，不能隐藏实现。

- `--read-only`是显式自说明选项，即使不传也只能只读。
- stdout纯JSON（单个最终结果对象或明确约定输出文件索引）；人类进度和日志stderr；JSONL事件另文件，不能混在JSON结果里。
- 内部UTF-8，JSON不加ANSI/banner；终端可ASCII fallback，未知TERM/无TTY不阻塞。
- `doctor`输出权限、OS、规则/工具完整性、输出能力、适配器可用性，不安装依赖、不联网。
- 退出码：0＝完整且无finding；1＝完整且有finding；2＝部分/受限/错误模块；3＝配置或会话致命失败；130＝取消。finding和缺项并存返回2，详情在报告。
- Ctrl+C优雅取消，二次中断只结束自家worker；进度和partial结果保存，不终止目标进程。
- 单模块超时和整个profile预算可配置；危险参数（全盘/跨挂载）首版不开放或明确二次确认范围。

### 10.3 TUI决策

首发CLI，后续TUI共用相同Session/事件，不另写规则。TUI加上下/Tab选模块、Enter详情、`/`搜索、Esc返回、q退出视图，80×24/resize/SSH编码/无TERM回退。不能因为没有TTY就不能扫描，退出视图不等于杀进程。不要在两天内为花哨终端布局牺牲Win7兼容或未扫状态。

## 11. 开发 Agent 执行协议与跨会话交接

### 11.1 可直接交给任意开发Agent的开工Prompt

```text
你是本项目的实施Agent。请把《离线CTF应急助手-全流程研发计划-v0.2.md》
作为研发主规范；用户希望最近两天首个可用版，但不允许虚构测试或压缩安全门禁。
先读主规范，再检查当前仓库；若已有实现，先读AGENTS/STATUS/TASKS/DECISIONS/
COVERAGE/TEST_RESULTS，禁止在不了解状态时从零重写。

第一版只读扫描、证据、解释、可复制的手工建议和JSON/HTML报告。
绝不实现自动修改、apply/fix、账户/任务/配置写操作、SFC/DISM修复、杀目标进程、
常驻服务、定时任务、内核驱动、遥测或远控。不得修改用户当前靶场，包括既有5/8进度。

主线C++17，Windows Win32 Unicode GUI+CLI、MSVC2022 v143 /MT；
Linux musl静态C++ x86_64 CLI，TUI以后。目标机不安装任何运行时。
先0—4小时兼容PoC，再薄纵向闭环，再按优先矩阵扩展。找不到合法VM或Windows宿主
要标记NOT_TESTED/BLOCKED；交叉编译和单元测试不冒充实机通过。

你负责研发全流程：准备获授权开发环境、依赖许可与hash审查、实现、编译、单测、
隔离VM测试、状态台账、打包、离线帮助。用户只做产物使用验收和反馈。
开发环境可按工具权限安装必要组件；生产/比赛靶机只接收便携包并只读运行。
软件开发请求不代表获准对真实目标执行修复或绕过安全策略。

现在输出简短资源盘点和当前phase，然后只实施当前phase。
每轮：读状态→选TASK→实现小变更→构建/测试→保存原始证据→更新台账→写下一步。
架构/OS下限/许可证/只读边界/主依赖改变必须先写ADR并升级关键决策。
不要反复向用户询问可自行确定的小细节，不要绑定特定Agent平台。
交付只列实际产物、hash、已测格、规则覆盖、已知限制、未测/失败项和用户验收步骤。
```

### 11.2 仓库状态文件规范

| 文件 | 必须内容 | 更新时机 |
|---|---|---|
| AGENTS.md | 红线、构建入口、依赖冻结、无真测禁止宣称、靶场边界 | 起步及关键规范变更 |
| PLAN.md | 本规范主版本/修订日志；不保留冲突第二主计划 | 需求变更 |
| STATUS.md | 当前phase、build/commit、最后成功命令、失败命令、阻塞、精确下一步 | 每轮结束/Agent切换前 |
| TASKS.md | ID、依赖、优先级、状态、负责人、验收、证据 | 领任务/完成任务 |
| DECISIONS.md | ADR编号、背景、选项、决策、官方依据、影响/回退 | 改重要决策之前 |
| COVERAGE.md | 每平台×模块×权限×来源；未实现/未测/限制 | 新模块/平台/回归后 |
| TEST_RESULTS.md | 命令、环境hash、预期、实际、退出码、日志路径、未运行原因 | 每次测试 |

状态枚举至少TODO/IN_PROGRESS/BLOCKED/IMPLEMENTED_NOT_TESTED/PASSED/FAILED/DEFERRED。`PASSED`需可定位证据，不以“Agent说应该可以”为证据。`STATUS.md`可以写下一条完整命令和预期产物，但不写密码/token。所有用户时间显示北京时间；API自带时区先转换。

### 11.3 每轮执行算法

1. 读取上述文件与当前git状态，识别已有改动；不覆盖其他Agent/用户未提交工作。
2. 从当前phase选依赖已满足的一项任务，说明范围，实施小步变更。
3. 构建相关target，跑单测/静态检查；能运行的隔离VM按用例验证。
4. 保存原始stdout/stderr、退出码、版本/hash；失败就保留，不删掉当未发生。
5. 更新TASKS/COVERAGE/TEST_RESULTS/STATUS；写清剩余风险和下一步。
6. 到phase门禁再集成；未过门禁不靠扩大并行掩盖。
7. 上下文不足时先写交接，不借此重写架构；下一个Agent从同文件续做。

### 11.4 并行规则

允许在schema与collector接口冻结后分 Windows backend、Linux backend、报告/测试三条独立任务；每条限定目录与接口。主集成Agent负责模型、构建和跨平台契约，不能两人各定义Finding。禁止共享同一worktree随意改同一文件；使用独立分支/worktree和小提交，由集成者合并。并行只能减少部分等待，不能创造VM、修复旧OS支持或替代真人使用验收。不得未经用户授权发布仓库、上传真实证据或外发消息。

### 11.5 只读权限与授权

开发Agent可在获准的开发环境执行构建/测试，但真实靶场的采集仍按授权范围；自动研发不等于自动处置。UAC只通过正常用户选择；Linux sudo不请求保存凭据。不使用已有浏览器会话/隐藏凭据绕过工具权限。若目标策略禁用传输或执行，报告限制与使用赛事批准方式，不教绕过。

## 12. 48小时里程碑与降范围顺序

### 12.1 前置资源

从实际开发启动时盘点：可用Windows构建宿主、合法Win7/2008R2镜像/VM运行权限、Linux构建/测试宿主、足够磁盘/内存、VM快照、依赖获取网络（仅研发阶段）、用户可接收ZIP方式。本文不假定这些已经具备。

资源准备耗时必须计入实际进度；若前4h仍无Windows运行条件，继续可做core/Linux/fixture，但Windows标阻塞/未测，告知48h全平台目标有风险，不改交付为用户不想要的WebApp。

**v0.3 开工实测（2026-11-08，全部只读探查）**：开发机 Win11 x64，VS2022 BuildTools v143 14.44.35207 已装、VS 自带 CMake 3.31.6、C 盘余 111GB；Win7 VM 192.168.0.14 实为 Windows7 Ultimate 7601 **SP1 x64**、SSH 免密可达（用户批复：允许 ctfir-marker 前缀夹具、测后清理并记录）；WSL Ubuntu-24.04 与 Docker Desktop 可用（centos-ir-lab 做 CentOS7 用户态验收；容器内核为 WSL2，内核 3.10 真机格另测）。M0 前置资源齐备，无 BLOCKED 项。

### 12.2 时间盒（可按证据调整，不是硬保证）

| 时间盒 | 输入→任务→产物 | 门禁/停止条件 |
|---|---|---|
| 0—4h M0兼容PoC | 资源台账；锁v143/SDK/musl；最小窗口/CLI；Unicode读写/hash；导入审计；旧系统启动；输出compat ledger | Win7失败优先修API/依赖；不扩规则掩盖。没镜像标未测，不能声称通过 |
| 4—10h M1薄闭环 | schema/session/状态/证据；Linux UID0＋Windows任务各一条规则；JSON/HTML＋最小GUI列表 | 从启动到可解释证据贯通；故障不能PASS；取消保partial；不能仅做mock界面 |
| 10—24h M2关键模块 | 两OS A模块优先（v0.3：含 W13 Web 起步规则×3）；B只基础采集；夹具正负/fault；只读建议模板 | 每已发布规则有最低样本与范围；缺模块公开DEFERRED，不伪填结果 |
| 24—36h M3界面整合 | GUI范围/结果/详情/漏项/日志；CLI契约；UTF-8/权限/取消；报告目录与帮助 | RDP1024与中文路径可用；UI后台运行；未完成检查可见；无修复入口 |
| 36—44h M4兼容/断网回归 | 干净VM、普通/高权限、零额外runtime、零DNS/HTTP、超时/坏数据/磁盘满 | 保证证据与状态；失败格不能入已支持；启动错误是阻塞而非补DLL凑数 |
| 44—48h M5发包/用户验收 | ZIP、hash、SBOM/licenses、手册/ledger/限制、5分钟验收；收一轮反馈 | 发布只读预览或已测MVP；列剩余项与下一版任务，不说全景完成 |

### 12.3 超时砍项顺序

先砍：TUI（本已后置）→跨会话diff→事件关联/漂亮图表→全量签名catalog增强→包离线解包比较→B模块深度规则/广遍历→P1系统扩展。保留A模块来源、真实状态、证据/解释、Windows最小可用GUI、CLI、JSON/HTML、只读边界、旧系统启动/依赖门禁与真实测试。

若A模块或主要P0格仍不能完成，发范围更小的预览版，明确缺项；不能删兼容声明里的失败项再对用户说“全部完成”。若没有足够证据安全发布，就交付可复现构建/失败日志/阻塞说明而非假成品。48h失败不触发自动安装运行库、全盘清理或绕过策略的“补救”。

### 12.4 与后续全景的关系

旧v0.1曾估计全景约230—390小时工程工作量（包括更广模块、完整UI、修复安全层和大矩阵回归）。这个数字不是现在的日历排期，也不能由“Agent全自动”直接除成两天。Agent可并行加速，但旧系统API、合法VM、真实测试、误报修正和用户反馈依然有串行成本。

当前只对48h最小版本时间盒；后续按实际吞吐与反馈排迭代，不预先排死日期、不将完整全景许诺在48h里。

## 13. 首批24个可直接建Issue的任务

| ID | 任务 /依赖 | DoD（完成定义）与验收例 |
|---|---|---|
| T01 | 资源/授权/范围台账；无依赖 | 列可用宿主/合法VM/缺失项/48h起点；不假设真实靶场可改 |
| T02 | AGENTS与状态文件；T01 | 八类交接文件齐全，任何新Agent可找当前phase/下一命令 |
| T03 | 许可与依赖锁；T01 | 每库精确版本/hash/授权；未知GScan代码不入库；原创许可仍提案 |
| T04 | Win32 /MT PoC；T03 | x86/x64窗口和CLI、中文读写；导入表；Win7/2008R2已测或标未测 |
| T05 | musl C++ PoC；T03 | x86_64通用指令、ELF依赖检查、CentOS7启动，失败原日志 |
| T06 | schema与模型；T02 | Session/Module/Evidence/Finding/Advice schema及未知版本拒绝测试 |
| T07 | scheduler与取消；T06 | 全终态、超时隔离、权限失败不PASS、partial恢复 |
| T08 | 安全文件读取/证据；T06 | 大小/链接/编码/元数据/hash，上限触发明确SKIPPED |
| T09 | Linux UID0纵向；T05-T08 | 一个真实collector→rule→advice→JSON/HTML，1正2负1fault |
| T10 | Windows任务纵向；T04,T06-T08 | COM递归含隐藏范围、XML证据与故障、GUI可见 |
| T11 | 报告与转义；T06,T09,T10 | 离线HTML/JSON，无外部资源，恶意字段不执行 |
| T12 | Linux SSH/cron；T09 | 各用户/系统来源，Include限制、公钥指纹、无私钥导出 |
| T13 | Linux profile/preload/hosts；T09 | 不source/加载库，行号/原文/误报说明与fault |
| T14 | Windows账户/组/界面隐藏；T10 | SID而非组名；隐藏≠SAM专题；权限拒绝不PASS |
| T15 | Windows服务/启动/hosts；T10 | 双位数注册表视图，未加载hive漏项说明，不写配置 |
| T16 | B类文件/包/进程基础；T12-T15 | 有字段/可信度/未支持标记，ps非唯一源；无基线不判完整性通过 |
| T17 | GUI最小完整交互；T07,T10,T11 | 总览/范围/结果/证据/漏项/日志、取消、复制建议、无执行按钮 |
| T18 | CLI/help/doctor；T07,T11 | stdout/stderr契约、退出码、无TTY、未知参数、明确拒绝fix |
| T19 | 普通/高权限回归；T12-T18 | 缺权限范围与提升只读选择实测，不安装broker服务 |
| T20 | 模糊/故障/隐私测试；T08-T18 | XXE/大输入/注入/空间满/坏DB/超时；结果不假通过 |
| T21 | 全净断网兼容；T04,T05,T19,T20 | 每格证据，零现场runtime安装、零DNS/HTTP；不能用mock代替 |
| T22 | RDP/scp手册与搬运测试；T21 | 合规传入→本地运行→报告导回；策略禁止时停止不绕 |
| T23 | 平台ZIP及发布清单；T03,T21,T22 | hash/SBOM/licenses/help/ledger/限制、Release非Debug包 |
| T24 | 用户5分钟验收及反馈回归；T23 | 收实际现象，Bug→fixture→修复→重发hash；未测格不扩大声明 |
| T25（v0.3） | Web 模块 W13 三条起步规则（web根定位/webshell特征/日志Top IP）；T12-T15 | 各规则 1正2负1fault；特征命中只列证据不定罪；只读不删webshell |

T09/T10是M0之后的最薄纵向切片；不允许跳过它们先写几十个检测文件。T16是有预算才深化的B类任务，不以未完成阻断其他已测A模块，但发行说明必须准确。

## 14. 测试规范与性能预算

### 14.1 GroundTruth与样本

每条发布规则最低1个正例、2个正常负例、1个权限/故障例。用隔离克隆机、无害marker配置、合成日志/注册表/任务XML夹具，不在当前5/8训练机中植入、清理或改分。需要真实OS API行为的例子在合法VM测试，不只测试解析器字符串。

GroundTruth由夹具清单＋独立人工/API核对建立，不由待测工具自己判自己。记录TP/FP/FN，precision=TP/(TP+FP)，recall=TP/(TP+FN)；样本有限，不能宣传100%真实世界检出。正常对象误报率给分母：误报正常对象数/已标注正常对象数；另列每主机高风险误报条数。

### 14.2 必测矩阵

1. 全净Win7SP1 x86/x64、2008R2SP1 x64与可得现代代表；无额外VC/.NET/Python安装。CentOS7与可得现代Linux。
2. 完全无互联网；若测试RDP/SSH搬运可保留授权隔离LAN，扫描进程不发DNS/HTTP、不连云；取包/开发下载不混入运行阶段。
3. 普通用户与admin/root；系统服务/任务权限拒绝、/proc hidepid、SELinux enforcing等限制能解释。
4. RDP传入、本地短路径运行、中文路径和用户名、1024×768/DPI；Linux无TERM/TTY、ASCII/UTF-8、SSH断连。
5. 输出NTFS/FAT32、ext4/xfs、只读目录、磁盘满、长路径/大文件/非法编码；未实测组合标未测。
6. 故障：损坏rpm DB、外部命令被替换、COM卡住、无systemd、进程瞬逝/PID复用、取消、程序崩溃和半写JSONL恢复。
7. 正常负例：合法cron/备份任务、授权key、重命名管理员、合法profile/alias、监控preload、软件升级deleted exe、离线证书链缺失。
8. 只读审计：配置前后内容/hash/权限等对照，无任务/服务/账户新增或修改；时间戳/事件日志等已声明副作用单列。

### 14.3 恶意输入与安全测试

- XML禁止DTD/XXE/外部实体；日志/JSON限大小、深度、文本长度和解析时间。
- 避免昂贵无界正则；首版尽量简单匹配/类型化条件。
- 路径遍历、循环链接、junction、重定向、shell元字符不能导致命令注入或越范围读。
- HTML对所有外来字段转义；不能把日志URL直接当可执行链接；不要在报告加载远程图片。
- 首版不处理外部压缩包；后续可信包解包前做路径穿越/炸弹防护，不执行安装脚本。
- 不保存完整进程环境，避免无关凭据；必要命令行可能含敏感信息，报告可脱敏，原证据按用户授权与ACL保存。

### 14.4 性能目标（未实测，不是事实）

在固定2vCPU/4GB/SSD隔离VM、有限目录10万文件测试集：GUI冷启动≤3秒，快速profile≤60秒，限定完整性profile≤5分钟，快速扫描峰值≤256MiB，每平台基础包≤40MiB（不含大基线）。单模块默认预算如5秒/30秒需要按API实际调优并记录；不能为了指标默认超时一堆模块还说扫全。

全盘hash取决于文件量，不做固定时间保证。资源不足时记录真实分解、调整预算或缩范围；保留原始测量、测试硬件和分母，不用AI估计代替性能实测。

### 14.5 MVP硬门禁

- 任何未扫/权限/超时/解析失败都不输出PASS。
- 任何已发布规则有最低样本与可追溯结果。
- 无未解释高风险FP，无冻结样本中未解释FN；如有则修正或撤下该规则并声明。
- 目标配置无未经授权修改；程序不存在可执行自动修复路径。
- 已宣称支持的格在干净目标上启动与断网闭环通过。
- 报告能打开、无外部依赖、证据可追溯、隐私保护有效。

## 15. 部署与搬运：Windows RDP、Linux scp

### 15.1 RDP事实和安全选择

微软文档确认RDP支持剪贴板文件复制粘贴及驱动器重定向，`\\tsclient\<盘符>`可访问重定向盘；KB2258090说明剪贴板复制大于2GB不支持，应使用其他允许方式。[S20/S21] 这**不等于**任何客户端都支持拖放；本计划不承诺拖拽。

服务器/域策略可禁用剪贴板/驱动器重定向并覆盖客户端选项，2008R2官方文档明确这一点。[S22] RDP能登录≠能传文件；能复制文字≠能复制文件。遇赛事禁用策略不修改GPO、不启用远程共享、不绕过限制，只用组织者批准的文件入口/介质。

最小暴露原则：优先通过允许的剪贴板复制单个交付ZIP；需要盘映射时，经典mstsc通常在“本地资源→详细信息→驱动器”选盘，不虚构任意文件夹映射功能。准备只存交付包/报告的独立小盘或专用虚拟盘（若客户端与赛事允许），仅勾该盘；若客户端本身支持文件夹共享，才选专用交付文件夹。**不要映射包含私人文档/凭据的整个C盘，不开所有驱动器，不开启额外SMB全盘共享。** 重定向通常使远端可读写本地盘，恶意目标可污染该介质。[S23]

### 15.2 Windows交付手册必须给出的步骤

1. 在可信个人电脑核对ZIP与SHA256；选择目标架构；准备仅交付资源，断开不需要的本地盘/剪贴板共享。
2. 通过允许的mstsc“显示选项→本地资源→剪贴板”文件复制粘贴，或“详细信息→驱动器”仅选专用盘；若策略禁用停止并使用批准入口。
3. 若专用盘为R:，远端资源管理器可访问 `\\tsclient\R\`（示例盘符，按实际替换）。从中**复制ZIP到靶机本地**如 `C:\CTFIR\`，解压后从本地运行。不要直接在重定向共享盘运行扫描/写证据，避免性能、权限与断连问题。
4. 非管理员先doctor，必要时用户显式UAC提升只读扫描；输出放本地私有目录，如有权限才用 `C:\CTFIR\out\`，不可写时选择用户本地目录。
5. 扫描完先看未完成检查，保存HTML/JSON；把需要的报告复制回交付盘/批准通道。原始敏感证据默认不广泛导回/分享。
6. 在可信机器把导回内容当不可信数据，先检查hash、只用安全文本/HTML查看，不自动运行任何目标生成的exe/脚本；结束后移除重定向。

复制粘贴失败手册按“客户端支持→选项→策略→文件大小→权限/空间”诊断；不建议关防火墙或绕策略。目标缺DLL/入口点时记录错误、OS/SP/架构、包hash；不现场下载陌生DLL，不安装runtime来掩盖MVP不兼容。

### 15.3 Linux scp示例（搬运命令，不是软件已实现）

以下用户名/主机/路径都是占位；用户替换为赛事授权信息，不能原样执行。工具通过已有获准SSH传输，不是扫描进程联网。

```sh
# 在个人电脑终端：拷入平台匹配的便携包
scp ./ctfir-linux-x86_64.zip USERNAME@HOST:~/ctfir-transfer/
# SSH中：使用已有系统解压工具解到本地专用目录；先核SHA256清单
# 只有对已核验的ctfir二进制设置执行位，再运行：
chmod u+x ./ctfir
./ctfir doctor
./ctfir scan --profile ctf --read-only --out ./out --format json > ./scan-result.json
# 回个人电脑终端：只拷回需要的报告
scp USERNAME@HOST:~/ctfir-transfer/out/report.html ./report.html
```

`ctfir-transfer`目录需事先按授权建立；ZIP内嵌套目录与示例路径由最终打包手册保持一致。若目标没有unzip，可另提供原始二进制＋文本规则/帮助清单或同内容tar包，不要求现场安装解压软件。普通用户chmod失败说明权限，不chmod整目录777。scp不可用/SSH旧算法不默认全局降级；仅经确认针对具体授权主机处理兼容，不改全局安全策略。无实际凭据写入命令、日志或git。

## 16. 发布清单与用户5分钟验收

### 16.1 每个平台交付内容

```text
ctfir-v0.1-<platform>-<arch>/
  <平台二进制：Windows含ctfir-gui.exe和ctfir.exe；Linux含ctfir>
  README-先读我.md
  使用说明.html
  rules/ 或明确声明规则编译内置
  schemas/
  SHA256SUMS
  BUILDINFO.json
  SBOM.json
  THIRD_PARTY_NOTICES.md
  licenses/
  COMPATIBILITY.md
  KNOWN_LIMITATIONS.md
```

上述平台二进制行是目录结构说明；实际命名必须统一。发行ZIP不含Debug runtime、真实证据、密钥、用户密码或Windows系统DLL。Windows不靠bat隐藏安装依赖；Linux提供便于无解压器环境搬运的原始二进制备选。每个包有hash与build/规则/schema版本。

- `COMPATIBILITY.md`列已测/未测格与环境，不能写“兼容所有Windows/Linux”。
- `KNOWN_LIMITATIONS.md`列未支持专题、权限/namespace/本地包DB信任、无基线完整性未知、深SAM/内核隐藏未覆盖。
- `README`给复制启动、RDP/scp搬运、5分钟验收、常见错误与卸载（删除工具/报告目录即可，不删除系统配置）。
- Release签名可在具备合法证书/密钥管理时做；未签名就说明未签名，hash需要独立可信来源核对，不能把自带hash当来源认证。首版外部规则包不热加载，因此不匆忙实现自创验签；后续签名规则包另门禁。
- 所有第三方授权/源码材料按实际义务随包提供；不把Sysinternals顺手塞入工具目录。

### 16.2 用户5分钟验收（时间是操作目标，扫描可更久）

1. 通过批准方式拿到正确架构包，复制本地短路径，核hash并打开GUI/CLI；记录是否缺DLL/入口点/被OS拒绝。
2. 看版本/OS/SP/权限/“只读”提示；普通权限doctor能解释受限项目。
3. 点“开始只读扫描”或CLI scan；观察真实模块状态；取消一次确认partial结果保留，再重新完整运行。
4. 打开一个finding或无finding模块的证据，能看路径/理由/误报/手工建议；复制建议不会执行；无“修复”动作。
5. 断网打开HTML，Ctrl+F查 `UID0` / `计划任务` / `未完成`；JSON可解析；导回报告；目标账户/任务/配置未被修改。

验收反馈不要求初学用户复核复杂算法；用户只需报告启动/操作/理解/漏项现象。Agent负责后续诊断与回归，不让用户反复下载安装依赖。第一次用户实机反馈后才可把对应兼容格标为用户实测，并保留证据。

### 16.3 发布硬停止

任何启动依赖错误出现在宣称支持格、未扫显示PASS、只读配置被改、HTML执行不可信内容、证据损坏无提示、许可证不明材料进入包，均停止该包正式发布。允许标注清楚的较小预览范围；不得静默改技术栈/绕目标限制以赶期。

## 17. 后续v0.x/v1.x全景与修复准入

| 版本方向 | 内容 | 进入条件 |
|---|---|---|
| v0.1首个可用 | 48h目标只读MVP，范围以实际已测为准 | 薄闭环、状态/证据/依赖门禁 |
| v0.2只读增强 | 补齐B模块、更多P1 OS、日志、diff、TUI、包基线、深度误报控制 | 每项新样本与VM回归，不回归丢旧格 |
| v0.x高级证据 | WMI、SAM元数据专题、可信介质/离线磁盘模式 | 隐私/授权/解析安全专项评审 |
| v1.x可控修复 | 计划→人工确认→最小权限执行→journal→回滚→复扫 | 用户重新明确批准需求＋安全与恢复门禁，不从v0暗中开启 |

未来修复设计保留：ActionPlan含目标身份/hash、前置条件、备份manifest、风险、回滚、计划摘要/有效期；执行前复核，TOCTOU/软硬链接/junction防护；保留Windows ACL/owner、Linuxowner/mode/ACL/xattrs/SELinux、任务原启用状态和注册表类型；失败中止、逆序回滚，无法回滚明确人工恢复。多步骤不保证OS级原子性。

未来broker必须短生命周期、严格IPC身份/SID或peer credentials、ACL、nonce防重放、命令白名单、类型化参数；不接收任意shell。没有越权/重放/任意命令测试通过就不开修复。

未来只先做可逆非关键项，优先禁用而非删除。账户/SSH/网络/防火墙/系统binary/驱动/核心服务高风险，只在专用向导、快照/带外访问、可信同版本恢复源就绪后考虑；永不全局一键删除/kill/清空cron/preload/SFC覆盖。疑似内核失陷时live结果低可信，修几个项不能证明系统恢复信任，可能需可信介质重建。

## 18. 反馈、回归闭环与文档修订

### 18.1 用户反馈模板

```text
工具版本/包SHA256：
OS/build/SP/架构（不知道可附doctor）：
运行方式：RDP/控制台/SSH；普通用户/管理员/root
发生时间（北京时间）：
期望：
实际：启动错误/扫描卡住/误报/漏项/看不懂/报告问题
最小复现步骤：
规则ID/模块ID/会话ID：
错误文字/截图/脱敏诊断文件：
是否取消、磁盘是否满、是否处于隔离网络：
```

不要要求上传密码、私钥、完整shadow/SAM或无关私人文件。真实题目原始证据先本地保留，向开发方共享前按用户选择脱敏。

### 18.2 Agent处理流程

反馈→分类（兼容/采集/规则/解释/UI/隐私/性能）→最小夹具→新增失败回归→修代码/规则→重测相关及旧平台→更新版本/hash/限制→交付用户复验。漏报不能只加关键字不测正常负例；兼容修复不能偷偷取消旧OS支持；解释错误也作为规则/文案回归。

### 18.3 当前修订日志

| 版本 | 日期（北京时间） | 变更 |
|---|---|---|
| v0.1 | 2026-11-08 | 初版全景研究，含长期工程量、双平台、可控修复设计 |
| v0.2 | 2026-11-08 | 改为独立Markdown交接主文件；Agent全程研发；48h只读MVP；移除首版自动修复/broker；SP1/RTM证据决策；RDP/scp搬运和Agent状态协议 |
| v0.3 | 2026-11-08 | 开工修订（用户批复三项）：项目定名 ctfir；Win7 x86 降 P1；新增 W13 Web 模块(A)与 L13 痕迹模块(B)；W05/W07/W08/W09 补次要持久化点/挖矿特征/粘滞键核对/登录日志首规则；Linux 构建定案 Alpine 静态；环境预盘点结论入 §12.1；新增 T25 |

当前实现/测试状态（2026-11-08 v0.3 开工）：仓库脚手架与 **M0 兼容 PoC 已完成并实测通过**（Win7 SP1 x64 真机 CLI/GUI 冒烟 + Linux 静态 CentOS7 用户态运行，证据见仓库 TEST_RESULTS.md）；其余功能均未实现。本文件中的接口、代码结构、性能/时间和平台列表仍是研发合同或目标，不能复制进“已完成功能”公告。

## 19. 来源、核实范围与未决条件

以下为2026-11-08（北京时间）研究依据；官方文档可能后续变化。构建锁定时保存所用版本许可/文档快照和hash，不把某网页日期当本程序测试日期。历史公告日期保持资料原意，不误作当前支持承诺。

| 编号 | 来源（准确URL） | 支持的结论/限制 |
|---|---|---|
| S01 | [微软MS17-010公告](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010) | 本轮打开；SP1受影响/更新表、未列版本的支持周期解释；不能推断RTM无漏洞或比赛SP1比例 |
| S02 | [Win7 CTF VM原始README](https://raw.githubusercontent.com/gsingh93/ctf-vm-windows7/master/README.md)；[仓库](https://github.com/gsingh93/ctf-vm-windows7) | 本轮打开；SP1构建和可去掉SP1脚本的一手实例；不是赛事总体统计 |
| S03 | [Solar训练合集](https://docs.qsnctf.com/Emergency_Response/solar-training-collection/) | 本轮搜索读取；培训材料列Win7/Server2019场景，未证SP1比例；非赛事主办方总体数据 |
| S04 | [MSVC目标平台](https://learn.microsoft.com/en-us/cpp/overview/supported-platforms-visual-cpp?view=msvc-170) | 本轮打开；VS2026不再target旧Windows，不能仅看表格X忽略脚注 |
| S05 | [微软C++生命周期FAQ](https://learn.microsoft.com/en-us/lifecycle/faq/visual-c-faq) | 前期同日核对；v143 14.44与工具生命周期，具体修订开发时冻结 |
| S06 | [微软/MT文档](https://learn.microsoft.com/en-us/cpp/build/reference/md-mt-ld-use-run-time-library?view=msvc-170) | 本轮打开；静态CRT与选项一致性，不保证全部依赖静态 |
| S07 | [UCRT部署](https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment?view=msvc-170) | 本轮打开；Win7SP1/UCRT部署与系统组件限制 |
| S08 | [Windows头文件版本宏](https://learn.microsoft.com/en-us/windows/win32/winprog/using-the-windows-headers) | 前期同日打开；宏控制声明，非二进制兼容证明 |
| S09 | [GScan README](https://raw.githubusercontent.com/grayddq/GScan/master/README.md) | 前期同日打开；CentOS6/7/Python和检查范围；许可尚未确认，根目录接口失败不是无许可的定论 |
| S10 | [Sysinternals EULA](https://learn.microsoft.com/en-us/sysinternals/license-terms)；[Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) | EULA本轮重新打开；免费专有与分发限制；不内置二进制 |
| S11 | [Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) | 前期同日打开；当前系统要求/签名hash能力，不能把最新版当Win7依赖 |
| S12 | [Velociraptor LICENSE](https://raw.githubusercontent.com/Velocidex/velociraptor/master/LICENSE)；[离线采集](https://docs.velociraptor.app/docs/deployment/offline_collections/) | LICENSE本轮重新打开；AGPLv3与离线采集边界，不等于自动修复 |
| S13 | [Qt所附LGPLv3全文](https://doc.qt.io/archives/qt-5.15/lgpl.html)；[Qt官方许可义务](https://www.qt.io/development/open-source-lgpl-obligations) | 前期同日核对；重链接/源码/通知条件，非法律保证 |
| S14 | [CMake静态MSVC runtime属性](https://cmake.org/cmake/help/latest/prop_tgt/MSVC_RUNTIME_LIBRARY.html) | 本轮打开；MultiThreaded、CMP0091；页面latest不代表工程可浮动使用最新CMake |
| S15 | [nlohmann/json v3.11.3 MIT](https://raw.githubusercontent.com/nlohmann/json/v3.11.3/LICENSE.MIT) | 本轮打开固定版本许可；安全/工具链评估仍是开工门禁 |
| S16 | [Qt6当前平台](https://doc.qt.io/qt-6/supported-platforms.html)；[Qt5.15历史平台](https://doc.qt.io/archives/qt-5.15/supported-platforms.html) | 前期同日核对；不作Win7主线，不把历史表当所有patch保证 |
| S17 | [Go1.21发行说明](https://go.dev/doc/go1.21) | 前期同日打开；最低Windows10/Server2016 |
| S18 | [musl介绍](https://musl.libc.org/about.html)；[musl FAQ](https://www.musl-libc.org/faq.html) | 前期同日打开；MIT/静态部署与C++专用工具链/兼容边界；FAQ历史信息不能替代精确版本实测 |
| S19 | [微软旧系统SHA-2支持](https://support.microsoft.com/en-us/servicing/os/windows/2020/09/2019-sha-2-code-signing-support-requirement-for-windows-and-wsus) | 同日搜索核对；旧系统更新签名基线，不保证任意代码证书离线验证 |
| S20 | [微软剪贴板文件2GB限制与tsclient示例](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/copying-2-gb-file-by-clipboard-redirection-fails) | 本轮打开；复制粘贴/驱动器重定向，不等于拖放 |
| S21 | [微软mstsc驱动器/tsclient说明](https://learn.microsoft.com/en-us/archive/blogs/brendangrant/the-most-useful-feature-of-remote-desktop-i-never-knew-about) | 本轮打开历史官方博客；盘选择与tsclient，不承诺文件夹映射 |
| S22 | [2008R2资源重定向与策略优先级](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc770631(v=ws.11)) | 本轮打开；服务端/策略可禁用并覆盖客户端 |
| S23 | [微软RDP重定向风险说明](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/understanding-security-warnings) | 本轮搜索核对；远端可读写本地盘/剪贴板风险；新客户端提示行为不外推所有旧客户端 |
| S24 | [RPM官方验证文档](https://rpm.org/docs/latest/man/rpm.8) | 前期同日搜索核对；本机DB基线、验证字段和noscripts；不等于恶意判定 |
| S25 | [微软Win7 SFC说明](https://learn.microsoft.com/en-us/previous-versions/technet-magazine/ff184577(v=msdn.10)) | 前期同日打开；可能需安装介质，首版不执行 |
| S26 | [RHEL7 glibc](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/7.0_release_notes/sect-red_hat_enterprise_linux-7.0_release_notes-compiler_and_tools-glibc)；[kernel3.10](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/7.4_release_notes/new_features_kernel) | 同日核对；CentOS7兼容设计参考，具体目标需实际镜像确认 |

### 19.1 尚待开发启动阶段实证，不是用户需求悬而未决

- Windows构建宿主与合法旧系统VM是否可用；无资源格只允许未测预览，不能宣称支持。
- MSVC2022/SDK精确修订、静态库导入与runtime行为；Linux musl C++/SHA256库精确版本、许可与hash。
- 原始SP1和SHA-2基线的签名链表现；无网络验证策略是否真正没有DNS/HTTP。
- 各系统RDP传输是否被政策允许、scp/本地执行路径；不绕过策略。
- 实际赛事若明确非SP1或其他架构，再触发legacy分支评估，不要求当前用户重新回答所有问题。

**最终执行原则：先兼容PoC，再薄闭环，再关键来源覆盖；把未完成如实写出来，比假装“一键扫全且安全”更重要。**
