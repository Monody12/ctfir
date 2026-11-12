# STATUS

- 阶段：**v0.6 完成**——R16 五点收尾 + 比赛防守考点补漏（Web GET 攻击日志、MySQL slow/binlog）+ 双平台发布包（本地提交，待确认后推送）
- 版本：kToolVersion **0.6.0** / 规则包 **6.0.0** / 检测点 **142**
- 门禁：见 TEST_RESULTS #39（本轮构建与回归数字）
- 考点对照：应急响应 / 基线核查 / 系统加固 / 日志审计 / 威胁溯源（主机侧）已覆盖；**业务数据恢复、动态流量、内存取证、内核 rootkit、ROW 格式 binlog 还原**属人工，KNOWN_LIMITATIONS 已写清
- 发布产物：`D:\ctfir-build\release\ctfir-v0.6-{windows-x64,linux-x86_64}.zip`（hash 见 TEST_RESULTS #39）
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

## 构建入口（固化）

- Win：`bash scripts/build-win.sh`（短路径 cmake/ninja；禁 .bat、禁 set PATH）
- Linux：`bash scripts/build-linux.sh`（单容器构建+测试+拷回）
- 产物：`D:\ctfir-build\{cmake-build,linux,release}\`

## 阻塞 / 风险

- 360 已卸载未重启：驱动残留仅影响已绕行两点；重启后补回归 #8/#9（WP9）。
- 本轮 **未 git push、未创建 GitHub Release**——待用户确认后再做。
- Server2008R2 / CentOS 3.10 真机格仍 NOT_TESTED（无合法镜像 / 容器为 WSL2 内核）。

## 失败记录

（本轮见 TEST_RESULTS #39；过程缺陷当场修复后全绿才打包。）
