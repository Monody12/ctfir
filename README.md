# ctfir — 离线 CTF 应急响应助手

> 只读扫描 · 中文解释 · 证据留痕 · 六步处置手册 · 目标机零运行时依赖

**ctfir** 是面向 CTF 线下赛应急响应（IR）赛道的 Windows / Linux 主机取证扫描工具：一条命令扫描账户、计划任务、服务、自启动、hosts、进程与网络连接、事件日志、webshell、执行痕迹等高频考点，输出**中文解释 + 原始证据 + 可人工执行的处置步骤**（JSON 与自包含 HTML 报告）。

三条不可协商的红线：

1. **只读为主**——默认扫描不修改目标机；v0.5 起可选受控 `fix`（白名单规则、需确认、先备份、支持 dry-run），默认不执行。
2. **离线**——代码中零网络 API；报告零外部资源，可断网打开。
3. **如实**——PASS 只代表"声明范围内未命中"；权限不足 / 超时 / 未覆盖项全部如实列出，不充当安全结论。

- **当前版本**：v0.6.1（规则包 6.0.1，2026-11-12）｜ 许可证 [MIT](LICENSE)
- **支持平台**：Windows 7 SP1+ x64 / Windows 10/11 x64（GUI + CLI）；Linux x86_64 静态二进制（CLI，CentOS 7 用户态已验）
- **完整兼容矩阵**：[packaging/COMPATIBILITY.md](packaging/COMPATIBILITY.md) ｜ 已知限制：[packaging/KNOWN_LIMITATIONS.md](packaging/KNOWN_LIMITATIONS.md)

---

## 一、给使用者

### 1.1 获取

- 从 [Releases](https://github.com/Monody12/ctfir/releases) 下载对应架构包（`ctfir-v0.6.1-windows-x64.zip` / `ctfir-v0.6.1-linux-x86_64.zip`），或自行构建（见开发者章节）。
- 复制整个目录到**目标机本地**（不要在共享盘直接运行），核对 `SHA256SUMS`。

### 1.2 图形界面（Windows）

双击 `ctfir-gui.exe`：

1. 顶栏会显示系统版本 / 位数 / 权限 / `[离线] [只读模式]` 标识；
2. 选择输出目录 → 点「开始只读扫描」；无管理员权限也能运行，受限模块会如实标注 `PERMISSION_DENIED`；
3. 发现列表点击任意条目 → 详情区展示证据原文、误报边界、处置建议；「复制建议」只复制文本；
4. 报告在输出目录：`report.html`（断网双击可看，Ctrl+F 检索）。

### 1.3 命令行（Windows / Linux 同构）

```bash
ctfir doctor                                  # 环境自检：OS/权限/已注册模块
ctfir scan --out ./out                        # 全量只读扫描
ctfir scan --out ./out --profile quick        # 快速档：只跑核心模块
ctfir scan --out ./out --dir /var/www         # 附加巡检目录
ctfir scan --out ./out --baseline hashes.txt  # 哈希基线比对（"路径 sha256" 每行）
ctfir explain --session ./out --finding <规则ID>   # 单条发现的证据+处置详解
ctfir report  --session ./out --redact        # 重新生成脱敏 HTML 报告
ctfir diff --a ./out-before --b ./out-after   # 处置前后复查：哪些消失/新出现
ctfir playbook user                           # 离线处置速查手册（见下表）
ctfir help                                    # 应急响应 15 分钟总纲
```

**退出码**：`0`=完整且无发现　`1`=有发现　`2`=部分/受限（权限、超时等）　`3`=致命错误。退出码与结果明细都以报告为准。

**playbook 手册类型**：`user` `logonhide` `task` `service` `startup` `hosts` `sshkey` `cron` `profile` `preload` `webshell` `process` `miner` `hash` `log`

### 1.4 怎么读报告

| 报告区块 | 含义 |
|---|---|
| 模块总览 | 每个模块的完成来源数 / 耗时 / 是否有线索 / 漏项与错误——**先看这里** |
| 发现 | 按"规则 ID + 风险 + 置信度 + 位置"列出；命中≠定罪，每条都附误报边界 |
| 未完成检查 | 权限不足 / 超时 / 不适用——这些不是安全结论 |
| 处置手册 | 六步制：**核实 → 留证 → 停用 → 清除 → 验证 → 复盘**，精确命令文本，停用先于删除 |
| 证据清单 | 每条证据的来源 / SHA256 / 留证文件，`integrity.sha256` 保证报告自洽 |

比赛场景建议：`--profile quick` 先跑一遍拿主线索 → 按处置手册人工清除 → `diff` 复查 → `--profile full` 终扫。考点↔规则对照见 [docs/KNOWLEDGE-MAP.md](docs/KNOWLEDGE-MAP.md)。

---

## 二、给开发者

### 2.1 架构

```text
ctfir.exe (CLI)  /  ctfir-gui.exe (Win32)
        └── Session / ScanConfig（调度：预算、取消保 partial、状态机、JSONL 事件）
                ├── platform/win/*   ← 19 个采集模块（COM / 注册表 / API / 文件）
                ├── platform/linux/* ← 12 个采集模块（/proc / /etc / 二进制解析）
                ├── 证据链（Evidence）→ 规则评估（Finding）→ 建议（Advice 六步制）
                └── 报告（JSON 终报 + 自包含 HTML，全字段转义）
```

- 平台模块只采证据；规则评估产出 Finding；Advice 只生成文本——**没有任何从扫描到执行的路径**。
- 状态机：`PASS / PERMISSION_DENIED / UNSUPPORTED / TIMEOUT / ERROR / SKIPPED`，权限失败永不输出 PASS。
- 所有输出统一 UTF-8，非 UTF-8 输入按字节保留并转义标注。

### 2.2 目录结构

| 路径 | 内容 |
|---|---|
| `core/` | 引擎：调度、数据契约（schema v1）、SHA-256、报告、建议库 |
| `platform/win/` | `mod_w/w2/w3.cpp` 三个模块族 + 公共助手（注册表双视图、路径提取器） |
| `platform/linux/` | `mod_a/b/c/d.cpp` 四个模块族 + 公共助手 |
| `docs/` | [DETECTION-POINTS.md](docs/DETECTION-POINTS.md)（100 检测点台账）、[KNOWLEDGE-MAP.md](docs/KNOWLEDGE-MAP.md)（考点映射） |
| `tests/` | 单测 + [cases/](tests/cases/) 声明式用例库 + 三套夹具生成器 |
| `scripts/` | 构建 / 测试 / 打包脚本 |
| `packaging/` | 发布包文档（README-先读我 / COMPATIBILITY / KNOWN_LIMITATIONS） |
| `PLAN.md` 等 8 份台账 | 研发规范与过程证据（见 2.6） |

**模块清单**（55+ 规则，检测点→规则溯源见 [docs/DETECTION-POINTS.md](docs/DETECTION-POINTS.md)）：

| 平台 | 模块 | 覆盖要点 |
|---|---|---|
| `WIN.*` | ACC / LOGINHIDE / SVC / AUTORUN / HOSTS / HASHES / TASKS / PROCNET / EVTLOG / WEB / PROCCMD / FILES / PREFETCH / SHIMCACHE / USB / RDPMRU / FIREWALL / SHARES / DRIVERS | 账户（含 4720-4732 生命周期时间线）、持久化全家（Run 双视图 / Winlogon / IFEO / AppInit / LSA / 登录脚本）、服务与驱动可写路径、任务事实化、登录爆破 Top IP、webshell 与 IIS 日志、进程命令行（WMI）+ 端口关联、基线比对、双扩展名、Prefetch / ShimCache / USBSTOR / RDP / 防火墙 / 共享 |
| `LNX.*` | ACC / SSH / CRON / SHELL / PRELOAD / HOSTS / TRACE / SYSTEMD / ELF / PROC / SUID / LOG / CAPS / AT / SHADOWPERM / TIMERFACT / FILES / WEB / LOGINS / LDSO | UID0 与重复 UID、sudoers、SSH 密钥（指纹，不采私钥）、cron/at/systemd 全来源、preload 与 ld.so.conf.d、profile/bashrc、历史与 lastlog/wtmp、SUID/capabilities、auth 日志、webshell 与 access 日志、基线比对 |

### 2.3 构建

前置：Windows 需 VS2022 BuildTools（v143 工具集 + C++ CMake 组件）；Linux 用 Docker。

```bash
# Windows x64（MSVC /MT 静态 CRT，产物在 D:\ctfir-build\cmake-build\）
bash scripts/build-win.sh

# Linux x86_64（Alpine 容器内 musl 静态编译，产物拷回 D:\ctfir-build\linux\）
bash scripts/build-linux.sh

# 发布打包（双平台 ZIP + SHA256SUMS + BUILDINFO + SBOM）
bash scripts/package.sh
```

要点（踩过的坑都固化在脚本里）：Windows 侧禁用 .bat 调 vcvars（改 bash 单行 + 8.3 短路径直呼 cmake/ninja）；编译目标 `_WIN32_WINNT=0x0601`；导入审计要求产物**零运行时依赖**（不得出现 UCRT/VCRUNTIME）。产物不落 C 盘（历史原因见 [TEST_RESULTS.md](TEST_RESULTS.md) #8）。

### 2.4 测试

| 层级 | 内容 | 运行方式 |
|---|---|---|
| 单元测试 | 引擎状态机、SHA-256 NIST 向量与填充边界、UTF-8 清洗、安全读文件、路径提取器、schema 拒绝（22 例） | 构建产物 `ctfir_tests`（双平台各跑一遍） |
| Linux 容器夹具 | `tests/fixture_linux.sh`：UID0 / cron / preload / hosts / history / SSH key / SUID / timer 正负例 + 权限拒绝 + 清理复验（24 项） | `bash scripts/test-linux.sh` |
| CentOS 真实环境 | `tests/fixture_builder_centos.sh`：在 centos-ir-lab（httpd/sshd/crond 常驻）部署 marker 夹具 → 扫描断言 → 清理复验（15 项） | `bash tests/fixture_builder_centos.sh <二进制>` |
| Win7 真机 | `tests/fixture_builder_win.sh`：外部独立验收矩阵八项断言（事实化/隐藏账户/参数路径/禁用任务/回环 hosts/基线/零误报/双扩展） | 需 `Administrator@192.168.0.14` 免密 SSH |

全套自动化（构建+单测+Windows 夹具+Linux 多发行版容器夹具）：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-all.ps1`。

**加新检测点的流程**（强制顺序）：先在 [docs/DETECTION-POINTS.md](docs/DETECTION-POINTS.md) 登记条目（来源 / ATT&CK ID / 正负例设计）→ 实现采集与规则 → `tests/cases/*.tsv` 加用例行 → 夹具断言通过 → 更新台账。每条规则最少 1 正例 + 2 负例 + 3 变体。

### 2.5 治理与过程文档

| 文件 | 用途 |
|---|---|
| [PLAN.md](PLAN.md) | 研发主规范 v0.3（需求、红线、架构、验收门禁） |
| [AGENTS.md](AGENTS.md) | Agent 执行协议摘要与构建入口 |
| [DECISIONS.md](DECISIONS.md) | ADR-001~008（x86 降级、Web 模块、Alpine 构建、版本锁定、开源决策等） |
| [COVERAGE.md](COVERAGE.md) | 平台×模块×权限覆盖矩阵（未测格如实标注） |
| [TEST_RESULTS.md](TEST_RESULTS.md) | 全部测试证据（命令、退出码、哈希、失败记录） |
| [TASKS.md](TASKS.md) | 任务看板 + 夹具登记（谁放的、清没清） |
| [STATUS.md](STATUS.md) | 当前阶段与下一步精确命令 |
| [BATCH-PLAN-M1M5.md](BATCH-PLAN-M1M5.md) | 无人值守批量执行计划（含自评循环收工判据） |

### 2.6 已知限制（摘要）

完整版见 [packaging/KNOWN_LIMITATIONS.md](packaging/KNOWN_LIMITATIONS.md)。重点：无内置可信基线（哈希只留证不判定篡改）；WMI 事件消费者 / 深层 SAM / 内核 rootkit / 内存取证未覆盖；ShimCache 为启发式提取；Windows 签名验证未接入；`diff` 仅对比 findings。Server 2008 R2 真 OS 与 CentOS 内核 3.10 真机无法在开发机容器中启动，已用合成事件 XML 与 centos:7 用户态夹具做自动化替代（不宣称这两格 PASSED），见 COMPATIBILITY 与 TEST_RESULTS #40。

---

## 三、贡献与许可

- 提交前跑通 `ctfir_tests` 双平台 + 对应夹具；新规则必须同时带正负例并更新 DETECTION-POINTS。
- 本项目不接受的贡献方向：任何形式的自动修复 / 执行器 / 联网能力（见红线）。
- 许可证 [MIT](LICENSE)；第三方组件清单见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与 [DEPENDENCIES.lock.json](DEPENDENCIES.lock.json)。
