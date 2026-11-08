# STATUS

- 阶段：**批量执行计划已拟定，等待用户批准**（[BATCH-PLAN-M1M5.md](BATCH-PLAN-M1M5.md)，批准后 WP0 起无人值守连续执行）
- 最后更新：2026-11-08 晚（北京时间）

## M0 门禁判定：PASS

| 门 | 结果 | 证据 |
|---|---|---|
| Win /MT x64 构建 + 导入审计 | PASS | TEST_RESULTS #7 |
| Win7 SP1 x64 真机启动（CLI+GUI） | PASS | #10 |
| Linux musl 静态构建 + CentOS7 用户态运行 | PASS | #11 |
| 兼容台账 | 已建 | COVERAGE.md |

## 环境异常登记（不阻塞，已绕行）

1. **360 残留过滤驱动**（360FsFlt/360Box64 SYSTEM_START、360AvFlt RUNNING）删 C 盘新建 PE；产物一律落 `D:\ctfir-build`。**2026-11-08 晚回归：用户在 UI 关闭"文件系统防护"无效**（驱动仍挂载，PE 秒删与 bat 失效均复现，见 TEST_RESULTS #12）；待用户**彻底卸载 360** 后回归 #8/#9。
2. **bat 上下文 vcvars 失效**：构建编排用 bash 单行（`poc/win/build_poc.sh`）；M1 CMake 同法。360 清理后复测。

## 下一步（M1 薄闭环，按 PLAN §12.2 4—10h 盒）

1. T03：nlohmann/json v3.11.3 下载→SHA256 锁定→安全公告核查→入 DEPENDENCIES.lock.json
2. CMake 工程（VS 自带 3.31.6，bash 单行调用）：core schema/模型 + 未知版本拒绝
3. scheduler/状态机（全终态、超时、取消保 partial）
4. T09 Linux UID0 纵向闭环（collector→rule→advice→JSON/HTML）
5. T10 Windows 任务纵向闭环（COM 枚举含隐藏 + GUI 可见）

## 风险

- Win7 GUI 仅自检通过，**视觉验收未做**（需 RDP/VM 控制台人眼确认，M3 补）。
- 360 残留驱动后续可能对 CLI EXE 也变卦（云信誉），关注每次重建哈希。
- Win7 VM 若被重建/还原（永恒之蓝实验遗留计划），夹具表与 C:\ctfir-test 需重建。
