# STATUS

- 阶段：**批量执行中——WP2 完成，WP3 进行中**（[BATCH-PLAN-M1M5.md](BATCH-PLAN-M1M5.md)）
- 最后更新：2026-11-08 深夜（北京时间）

## 已完成

| WP | 结果 | 证据 |
|---|---|---|
| WP0 | 仓库 github.com/Monody12/ctfir 建立+首推（MIT，ADR-007） | TEST_RESULTS #15 |
| WP1 | nlohmann v3.12.0 锁版(ADR-008)；CMake+Ninja 工程；导入审计零运行时 | #15 |
| WP2 | schema/模型/scheduler/安全读取 + 单测 **双平台 15/15** | #15 |

## 当前 WP3 精确下一步

1. `platform/linux/modules.cpp` 实现 L01-L13 collectors+rules（UID0/SSH/cron/profile/preload/hosts/痕迹/ELF/进程/SUID/日志）
2. 容器夹具正负例测试（临时容器内造 marker → scan → 断言）
3. Windows 侧回归（不影响 WP3，可后跑）

## 构建入口（固化）

- Win：`bash scripts/build-win.sh`（短路径 cmake/ninja；禁 .bat、禁 set PATH）
- Linux：`bash scripts/build-linux.sh`（单容器构建+测试+拷回）
- 产物：`D:\ctfir-build\{cmake-build,linux}\`

## 阻塞 / 风险

- 360 已卸载未重启：驱动残留仅影响已绕行两点；重启后补回归 #8/#9（WP9）。
- 无。开发主链畅通。

## 失败记录

（本轮无；#15 记录了三处过程缺陷及修复）
