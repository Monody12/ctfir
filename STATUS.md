# STATUS

- 阶段：**批量执行中——**批量执行完成（WP0-WP8）——待用户验收；剩余：360 重启回归/Server2008R2/CentOS3.10 真机格****（[BATCH-PLAN-M1M5.md](BATCH-PLAN-M1M5.md)）
- 最后更新：2026-11-08 深夜（北京时间）

## 已完成

| WP | 结果 | 证据 |
|---|---|---|
| WP0 | 仓库 github.com/Monody12/ctfir 建立+首推（MIT，ADR-007） | TEST_RESULTS #15 |
| WP1 | nlohmann v3.12.0 锁版(ADR-008)；CMake+Ninja 工程；导入审计零运行时 | #15 |
| WP2 | schema/模型/scheduler/安全读取 + 单测 **双平台 15/15** | #15 |
| WP3 | Linux 12 模块 + 18 规则；容器夹具 **24/24**（正/负/fault/清理） | #16 |
| WP4 | Windows 10 模块 + 17 规则；Win7 真机夹具 **6/6 命中 0 残留** | #17 |

## 当前 WP4 精确下一步

1. platform/win/mod_w.cpp：W01 账户(NetUserEnum/SID)/W02 UserList/W03 任务(COM)/W04 服务(SCM)/W05 自启动+次要持久化点/W06 hosts/W13 Web 三规则
2. Win7 VM ctfir-marker 夹具（任务/用户/hosts/启动项/服务）→ 正负例
3. W07/W08/W09 基础采集（进程/哈希/事件日志）

## 构建入口（固化）

- Win：`bash scripts/build-win.sh`（短路径 cmake/ninja；禁 .bat、禁 set PATH）
- Linux：`bash scripts/build-linux.sh`（单容器构建+测试+拷回）
- 产物：`D:\ctfir-build\{cmake-build,linux}\`

## 阻塞 / 风险

- 360 已卸载未重启：驱动残留仅影响已绕行两点；重启后补回归 #8/#9（WP9）。
- 无。开发主链畅通。

## 失败记录

（本轮无；#15 记录了三处过程缺陷及修复）
