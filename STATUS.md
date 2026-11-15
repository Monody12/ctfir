> **0.8.7 当前账户安全策略**：继续禁止全部自动修改；增加本地SAM/DC隔离、SID/RID证据、PS5.1只读预览与严格Linux UID解析。见 ACCOUNT_COMPAT_087.md。Server2016尚未真机验证，CI宿主不冒充2016；CentOS按实际用户态版本记录。下方旧版记录按原时间理解。

> **0.8.6 安全告警与当前策略（2026-11-15，北京时间）**：旧版 fix 与旧处置建议不再有效。自动修改白名单现为空，所有平台仅扫描/报告/只读预览；旧plan、--yes、--all、未知动作均不能执行修改。下方旧版“修复成功/白名单/一键删除”等记录是历史，不是当前操作指引。不得修改题目保护的root密码/SSH公钥，不能按共享UID终止进程或递归删除home。

# STATUS

- 当前版本：**0.8.7** / 规则包 **7.2.5** / 检测点 **192**。
- 本轮定向修复：隐藏 SUID/cron/systemd/常驻进程、报告噪声、禁止按进程快照给 STOP/KILL。CI优先验证记录：`43612183540` 双平台 success，Win116/Linux112 单测；四版新增回归76/76；基础Win29、Linux各43，另高频/GUI/hidepid通过，见 TEST_RESULTS #45。最终包仅从对应准确提交成功CI取产物，正式Release状态以 GitHub v0.8.5 查询为准。
- 当前 Kali 未保留四处历史植入对象；没有改动/清理其配置、证据或进程，不冒称原 10 点场景通过。

## v0.8.4 历史发布状态
- 发布准备在 box 进行；Windows 原工作区和 JW2026/exam-hf 待练环境均未修改。
- 发布门禁全绿（TEST_RESULTS **#44**）：Win 单测 109/109 + 基础夹具29/29 + 高频16/16 + GUI自检；Linux 单测105/105 + 四发行版各43/43 + 高频59/59 + hidepid。严格CI：`https://github.com/Monody12/ctfir/actions/runs/43600451232`。
- 正式发布 tag：`v0.8.4`；最终提交与包的准确映射以 BUILDINFO.source_commit 和对应 tag CI 为准。发布操作仍必须在最终文档提交CI通过后进行，不覆盖现有tag/资产。
- 旧 STATUS 的 Win 106/Linux 102/Win7 33 HIT 摘要仅作为迁移前历史声明，不充当本轮可复核日志。
- 产物由准确提交的 CI 生成，BUILDINFO 含 commit/tree/规则版本/规则源码摘要/二进制 SHA256；禁止用旧 ci-pkg 或旧 ZIP 冒充本版。
- 本轮源码快照 SHA256：`f5b5e846fb5570fa563c8ee4818ca929f2b3b8dc3da930b38d365e7c77b582fa`（155 文件，基线 b95b53b）。
- 最后更新：2026-11-14（北京时间）。

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
| v0.8.0 | WIN.AD.* + Server 凭据防护；Win7 analog 42/42；contest-fix 不关 Spooler；cleanup 恢复（Netlogon 实验室原值仍报） | #43 |

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
