# ctfir — Agent 执行协议

主规范：[PLAN.md](PLAN.md)（v0.3，2026-11-08）。冲突时以 PLAN.md 为准；本文是执行摘要与红线。

## 红线（不可协商）

1. **只读扫描＋文本建议**。无 apply/fix、无写动作执行器、无 SFC/DISM、不杀目标进程、不禁用/删除任何配置。
2. 无远控、联网、遥测、自动下载、开机服务、计划任务自启、内核驱动、安全控制绕过。
3. 不抓凭据；不保存 SAM/shadow 哈希、私钥、密码。证据字段（用户名/路径/IP/公钥指纹）按授权保留。
4. 目标机零运行时依赖：Windows `/MT` 静态 CRT，Linux musl 静态。禁止拷贝来路不明 DLL。
5. 不动用户训练/计分环境（既有"5/8"进度原状）。
6. Win7 VM（192.168.0.14）为用户授权实验机：允许 **`ctfir-marker` 前缀夹具**，测试后清理并在 TASKS.md 夹具表登记；除此之外不做破坏性改动。

## 构建入口（M0 实测定型）

| 目标 | 命令 | 说明 |
|---|---|---|
| Win PoC | `bash poc/win/build_poc.sh` | bash 编排 cmd 单行调 vcvars；**产物 → D:\ctfir-build** |
| Linux PoC | docker alpine g++ -static（见 TEST_RESULTS #11） | musl 静态 |
| Win7 部署 | `scp → C:\ctfir-test\`，ssh 冒烟 | 免密 `Administrator@192.168.0.14` |

- **禁止用 .bat 调 vcvars**（本机 bat 上下文全机失效，见 TEST_RESULTS #9）；M1 CMake 用同款 bash 单行调用。
- **禁止把 PE 产物写到 C 盘**（360 残留驱动秒删，见 #8）；仓库内不留 EXE。

## 环境事实（2026-11-08 实测，只读探查）

- 开发机 Win11 x64；VS2022 BuildTools **v143 14.44.35207**；VS 自带 CMake 3.31.6；C 盘余 111GB。
- **360 残留过滤驱动在场**（360FsFlt/360Box64 SYSTEM_START + 360AvFlt RUNNING；程序本体已停用）：删 C 盘新建 PE、干扰 bat 执行。用户待清理/加白；产物走 D 盘绕行。
- Win7 VM：Windows7 **Ultimate 7601 SP1 x64**（正是 P0 目标格），SSH 免密；部署目录 `C:\ctfir-test\`。
- WSL Ubuntu-24.04；Docker Desktop（CentOS 用户态验收用 `centos7-full:latest`，即用户所说 centos-ir-lab 的镜像；容器内核=WSL2，≠3.10）。

## 台账纪律

- `PASSED` 必须有可定位证据（命令+退出码+输出摘录+哈希）；未测＝`NOT_TESTED`；交叉编译/单测不冒充实机通过。
- 时间统一北京时间；STATUS.md 不写密码/token。
- 每轮：读状态→选 TASK→小步实现→构建/测试→记录→更新台账。
