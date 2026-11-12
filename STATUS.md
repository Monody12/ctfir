# STATUS

- 阶段：**v0.6.1 完成**——原 manual / NOT_TESTED / 依赖开发机真实数据的测试点全部改为自建环境的可重复自动化用例（一条命令 `scripts/test-all.ps1`）；工具 0.6 检测能力上的测试完善与若干解析/路径补齐。本地提交，**先不 push、不开 Release**，待确认。
- 版本：kToolVersion **0.6.1** / 规则包 **6.0.1** / 检测点 **142**（无新规则 ID；Windows 补齐已有 MID.MYSQL.*；EventID Qualifiers 与 BootExecute MULTI_SZ 为修复）
- 门禁：见 TEST_RESULTS **#40**（全平台构建 + 全套自动化测试数字）
- 考点对照：应急响应 / 基线核查 / 系统加固 / 日志审计 / 威胁溯源（主机侧）已覆盖；**业务数据恢复、动态流量、内存取证、内核 rootkit、ROW 格式 binlog 还原**属未实现范围（非“未写测试”），KNOWN_LIMITATIONS 已写清
- 发布产物：`D:\ctfir-build\release\ctfir-v0.6.1-{windows-x64,linux-x86_64}.zip`（hash 见 TEST_RESULTS #40）——二进制已变，需重出包
- 最后更新：2026-11-12（北京时间）

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

## 构建入口（固化）

- Win：`bash scripts/build-win.sh`（短路径 cmake/ninja；禁 .bat、禁 set PATH）。若本机 Git Bash 下 `cmd //c` 为空操作，`scripts/test-all.ps1` 会回退到 `cmd.exe /c` + vcvars64 + cmake（与手工成功路径相同）。
- Linux：`bash scripts/build-linux.sh`（单容器构建+测试+拷回）
- 全套自动化：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test-all.ps1`
- 产物：`D:\ctfir-build\{cmake-build,linux,release}\`

## 阻塞 / 风险

- 360 已卸载未重启：驱动残留仅影响已绕行两点；重启后补回归 #8/#9（WP9）。
- 本轮 **未 git push、未创建 GitHub Release**——待用户确认后再做。
- **真实 CentOS 3.10 内核**与 **Server 2008 R2 操作系统**无法在本开发机用容器启动（技术原因见 #40 / COMPATIBILITY）；已用用户态镜像 + 合成事件 XML 做最接近的自动化替代，**不把这两格标 PASSED**。

## 失败记录

（本轮见 TEST_RESULTS #40；过程缺陷当场修复后全绿才打包。）
