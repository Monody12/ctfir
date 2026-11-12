# STATUS

- 阶段：**v0.7.0 收口**——处置工作台 + CI 修复 + 宿主兼容警告 + `ctfir actions` 急救清单 + Linux musl 回归。GUI 仍只读，无修复按钮，不做 360/SFC。
- 版本：kToolVersion **0.7.0** / 规则包 **6.0.1** / 检测点仍 **142**
- 门禁：TEST_RESULTS **#41**（工作台）+ **#42**（CI / 兼容 / Linux）
- 考点对照：个人赛安全防护 + 团队赛主机侧（`--profile full`）。Win7 RTM / x86 未交付，见 ADR-010。
- 发布产物：Windows `D:\ctfir-build\cmake-build\`；Linux `D:\ctfir-build\linux\`。push `main` 走 `.github/workflows/ci.yml` 上传 Artifact；tag `v*` 发 Release。
- 最后更新：2026-11-12 23:40（北京时间）

## 已完成

| WP | 结果 | 证据 |
|---|---|---|
| WP0 | 仓库 github.com/Monody12/ctfir 建立+首推（MIT，ADR-007） | TEST_RESULTS #15 |
| WP1 | nlohmann v3.12.0 锁版(ADR-008)；CMake+Ninja 工程；导入审计零运行时 | #15 |
| WP2 | schema/模型/scheduler/安全读取 + 单测 **双平台** | #15 |
| WP3 | Linux 模块 + 规则；容器夹具正/负/fault/清理 | #16 及后续 |
| WP4 | Windows 模块 + 规则；Win7 真机夹具 | #17 及后续 |
| v0.5 | 受控 fix 引擎 + R10–R15 考点/修复闭环 | #24–#38 |
| v0.6 | R16 五点 + 日志取证补漏 + 版本升至 0.6 | #39 |
| v0.6.1 | 原 manual 全自动化；Win MySQL 路径；2008R2 XML / CentOS7 用户态替代；一条命令全绿 | #40 |
| v0.7.0 | 处置工作台：分桶/排序/过滤/已填命令/现代 HTML+Win32 GUI；Startup 脚本可见；微软 Active Setup 进清单 | #41 |
| v0.7.0+#42 | CI（windows-2022 + zip-utf8 + push Artifact）；doctor 兼容警告；`ctfir actions`；Linux 0.7.0 五发行版 42/42 | #42 |

## 构建入口（固化）

- Win：`bash scripts/build-win.sh`（短路径 cmake/ninja；禁 .bat、禁 set PATH）。若本机 Git Bash 下 `cmd //c` 为空操作，`scripts/test-all.ps1` 会回退到 `cmd.exe /c` + vcvars64 + cmake（与手工成功路径相同）。
- Linux：`bash scripts/build-linux.sh`（单容器构建+测试+拷回）
- 全套自动化：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test-all.ps1`
- 产物：`D:\ctfir-build\{cmake-build,linux,release}\`

## 阻塞 / 风险

- 360 已卸载未重启：驱动残留仅影响已绕行两点；重启后补回归 #8/#9（WP9）。
- GitHub Actions 曾因 `windows-latest`=VS18 以及 `tar -a` 退出码 1 失败（run 43238548478）。已改 `windows-2022` + Python zip，并加 `ci.yml` 使 push 即可下载 Artifact。
- **真实 CentOS 3.10 内核**与 **Server 2008 R2 操作系统**无法在本开发机用容器启动（技术原因见 #40 / COMPATIBILITY）；已用用户态镜像 + 合成事件 XML 做最接近的自动化替代，**不把这两格标 PASSED**。

## 失败记录

（v0.6.1 见 #40；v0.7.0 见 #41。过程缺陷当场修复后才记 PASSED。）
