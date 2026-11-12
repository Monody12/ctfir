# COMPATIBILITY — 已测/未测平台格（诚实声明）

发布只承诺“本表已测格”；未测格不代表不支持，只代表未验证。无法容器化的格给出自动化替代，**不把替代写成该 OS/内核已 PASSED**。

## 已测（有证据，见 TEST_RESULTS.md）

| 平台格 | 版本细节 | CLI | GUI | 证据 |
|---|---|---|---|---|
| Windows 7 Ultimate SP1 x64 | build 7601，裸机级 VM | ✅ 全命令矩阵+夹具 | ✅ 视觉验收+自检 | #10 #17 #18 |
| Windows 11 x64（开发机，内核 26100） | 管理员 + 完整 fixture_win 29/29 | ✅ | ✅ 自检 | #7 #15 #19 #40 |
| CentOS 7 x86_64 用户态 | centos:7 与 centos-ir-lab（glibc 2.17），musl 静态二进制 | ✅ 夹具 42/42 与 75/75 | 无 GUI | #11 #19 #40 |
| Alpine 3.20 | 构建与夹具容器 | ✅ 42/42 + 单测 55/55 + hidepid | 无 GUI | #40 |
| debian:8 / ubuntu:16.04 用户态 | 同一 musl 静态二进制 | ✅ 各 42/42 | 无 GUI | #40 |
| Ubuntu 24.04 (WSL2) | 静态二进制 | ✅ 自检 | 无 GUI | #11 |

## 自动化替代（无法提供真实 OS/内核，见 TEST_RESULTS #40）

- **Windows Server 2008 R2 SP1 x64 真 OS**：Windows 容器必须匹配宿主内核，无法在 Win11 10.0.26100 上运行 2008 R2 容器；合法完整镜像亦不可随意获取。替代：`tests/test_evt_xml.cpp` 用 2008 R2 形态事件 XML（`<EventID Qualifiers="16384">7045</EventID>` 及 4697）**5/5 PASS**；工具以 `_WIN32_WINNT=0x0601` 编译，相关 API 由本机 Win11 上的 `fixture_win.py` 行使。不宣称 2008 R2 操作系统已测。
- **CentOS 7 内核 3.10 真机**：Docker 共享宿主内核（本开发机为 WSL2 `6.6.87.2-microsoft-standard-WSL2`），容器无法换核。替代：centos:7 / centos-ir-lab **用户态**全套夹具（42/42 与 75/75）。未搭建 QEMU 3.10 虚拟机。不宣称 3.10 内核已测。

## 仍未在该精确版本上运行（技术原因，非空标 manual）

- Win7 SP1 x86（ADR-001：构建配置保留，首版不打包 x86）
- Windows 10 22H2：本宿主是 Win11 26100，没有 22H2 映像，不标 PASSED
- Windows 8/8.1、其他未列出的发行版 build
- 只读文件系统/ext4 之外的异常输出介质组合（未单独建磁盘矩阵）

## 已知环境限制

- 深层 SAM / RID 劫持、内核级 rootkit、内存取证、磁盘镜像模式：**未实现**（C 级）
- 包管理器校验（rpm -V / dpkg -V）：未实现适配器（不冒充已检查）
- wtmp/last 二进制、journalctl：未解析（线索以 auth.log/secure 为准）
- 事件日志 Security 通道：需要管理员；受限令牌下如实报 PERMISSION_DENIED
- shell 配置静态解析，不 source 不执行；动态拼接无法求值（报告中说明）
- 测试为制造真实 7045/4697 会创建临服务，测后 `sc delete`；**不清理事件通道**（破坏性），故事件残留是预期现象
