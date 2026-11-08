# DECISIONS（ADR）

格式：编号 / 背景 / 决策 / 理由与依据 / 影响与回退。

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
