# TEST_RESULTS

记录格式：日期(北京) / 环境 / 命令 / 预期 / 实际(退出码) / 产物hash / 结论。失败原样保留。

## 2026-11-08 环境预盘点（只读探查）

| # | 探查 | 结果 |
|---|---|---|
| 1 | VS2022 BuildTools + VC x86/x64 工具集 | 已装，v143 **14.44.35207**（vswhere 确认） |
| 2 | VS 自带 CMake | 3.31.6-msvc6（ADR-004 锁定） |
| 3 | Win7 VM 版本（reg query 经 ssh） | ProductName=Windows 7 Ultimate，CurrentBuild=7601，CSDVersion=Service Pack 1，ARCH=AMD64 |
| 4 | SSH 免密 | `ssh Administrator@192.168.0.14` BatchMode 可达，whoami=win-iei7iuc47k7\administrator |
| 5 | C 盘剩余 | 111GB |
| 6 | WSL / Docker | Ubuntu-24.04；docker images 可列（centos7-full:latest + centos:7 为 CentOS 用户态验收镜像，centos-ir-lab 为其容器实例） |

## 2026-11-08 M0 PoC（T04/T05）

**#7 Win 构建（T04）**：`poc/win/build_poc.sh`（vcvars64 短路径 + cl /MT /EHsc /utf-8 /D_WIN32_WINNT=0x0601，产物 → D:\ctfir-build）
- ctfir-poc-cli.exe：dumpbin 导入面 = **KERNEL32.dll + bcrypt.dll**（无 UCRT/VCRUNTIME，/MT 静态生效）✓
- ctfir-poc-gui.exe：导入面 = **USER32 + SHELL32 + KERNEL32**（同上零运行时）✓
- Win11 本机冒烟：CLI utf8 中文 + sha256("abc") 向量 PASS，exit=0；GUI --selftest 写结果文件 `ctfir-gui-selftest OK`，exit=0 ✓

**#8 环境异常：C 盘新建 PE 被秒删（根因查明）**
- 现象：GUI 子系统 EXE 链接成功后 **<1 秒内消失**；换名（gui-probe-a/b）、换扩展（.poc）、加版本资源段均无效；内容等价的控制台 EXE 及其副本存活。
- 根因：**360 杀毒残留内核过滤驱动仍在实时拦截**：`360FsFlt`/`360Box64`（SYSTEM_START）、`360AvFlt`（DEMAND_START），全部 RUNNING；360 程序本体已停用（C:\ProgramData\360safe\360Disabled）；Defender RealTime=False；Kaspersky 未安装（SecurityCenter2 注册为残留）。
- 处置：构建产物目录定为 **D:\ctfir-build**（D 盘写入存活，实验通过）。**待用户**：彻底清理 360 残留或对构建目录加白；清理后回归验证 #9 与 C 盘输出。

**#9 环境异常：bat 上下文调用 vcvars 全机失效**
- 现象：任何 .bat 内 `call vcvars64.bat`（全路径带引号 / 8.3 短路径、C: 与 D: 均试）失败，报"系统找不到指定的路径"/"文件名、目录名或卷标语法不正确"；**同一命令经 bash 单行 `cmd //c 'call … && cl …'` 稳定可用**（DIRECT_OK 对照）。
- 决策：构建编排一律用 bash 单行（M1 CMake 同法调用）；该异常在 360 清理后回归复测。

**#10 Win7 SP1 x64 真机冒烟（T04 门禁）**
- scp 两 EXE → `C:\ctfir-test\`，ssh 执行：
  - CLI：utf8 中文输出 ✓、sha256 selftest **PASS**、exit=0
  - GUI `--selftest --out`：window_created=1、message_pumped=1500ms、结果文件写入 ✓、exit=0（视觉验收留待 RDP/VM 控制台，见 STATUS 风险）
- 哈希两端一致（certutil vs sha256sum）：
  - cli `40dd47ed57944fc56391081810562d86b2a7c95e386a12d8e7cb120cad137206`
  - gui `b9c2005cecdd7080e8f71ac2b41c5a36e01fd93c3e511209159b92b4432ef146`
- 结论：**T04 PASSED**（x64；x86 按 ADR-001 DEFERRED）

**#11 Linux 构建（T05）**
- `alpine:3.20`（digest d9e853e8…）`g++ -std=c++17 -O2 -Wall -static` → ctfir-poc-linux，sha256 `3332fcf08853e90a2743de9a6303ea4fc4a449bcf69dfdfc580f5f96dfea44ab`
- 自实现 SHA-256（FIPS 180-4）向量 PASS；`ldd` 报 Not a dynamic program = 纯静态 ✓
- 运行验收：centos7-full:latest（glibc 2.17 用户态）exit=0 PASS；WSL Ubuntu-24.04 PASS
- **内核 3.10 真机格：NOT_TESTED**（docker=WSL2 内核，无等价环境）
- 结论：**T05 PASSED**（静态 x86_64 通用基线）

## 2026-11-08 晚 回归复测（#12：用户在 360 UI 关闭"文件系统防护"之后）

- `fltmc filters`：**360Box64 / 360FsFlt / 360AvFlt 仍在挂载**（UI 关防护 ≠ 卸载驱动）。
- C 盘 PE 秒删：**仍存在**（GUI EXE 链接成功后 <2s 消失，c-probe-gui 实验）。
- bat 调 vcvars：**仍失效**（完整输出仅一行"系统找不到指定的路径"，无 banner）。
- 本轮排除：cmd AutoRun（HKCU/HKLM 均空）；bat→bat 相对路径 call 正常（链式实验 RET=0）→ bat 失效为 vcvars 调用特有，是否 360 所致待彻底卸载后判定。
- 结论：绕行方案（产物走 `D:\ctfir-build` + bash 单行构建编排）**继续有效，开发不受阻**；#8/#9 的最终回归待用户**彻底卸载 360**（UI 关防护不够）后复测。

## 2026-11-08 晚 回归复测 #13（用户将 `C:\Users\Administrator\Documents\zcode-projects` 加入 360 文件白名单后）

- 实验：在白名单目录内重建 GUI PE（c-probe-gui.exe），链接成功（LINKED）。
- 结果：**白名单无效** —— 2s/10s/30s/60s 轮询全 GONE（与 #12 行为一致）。
- 分析：删除行为与"扫描/文件白名单"不同源（此前"文件系统防护"关闭也未阻止删除，#12）；删除者疑似 360 的云查杀/QVM 行为引擎，其信任判定不走文件白名单。
- 结论：**绕行（D:\ctfir-build）仍是唯一稳定方案**；根治只剩"彻底卸载 360 后重启"一条路（备选：多引擎设置里逐个关云查杀/QVM 试错，每轮需复测，性价比低）。

## 2026-11-08 晚 回归复测 #14（用户尝试关闭云查杀引擎后）

- 状态：文件系统防护已关 + 文件白名单已加 + **云查杀引擎无法在 UI 关闭**（用户截图：360云查杀引擎"已开启"，无关闭入口）。
- 实验：白名单目录内重建 GUI PE → LINKED → 2s/10s/30s 全 GONE。
- 定案：**删除者=360 云查杀引擎**（对无信誉新编译 GUI PE 云端判杀，不受文件白名单/文件系统防护开关约束，且 UI 不可关）。
- 待办：用户彻底卸载 360 + 重启 → 复测 #8（C盘PE）/ #9（bat调vcvars）两项，通过后可将产物目录迁回仓库（或保留 D:\ctfir-build，见 STATUS 决策）。
