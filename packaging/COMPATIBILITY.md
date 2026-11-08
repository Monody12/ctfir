# COMPATIBILITY — 已测/未测平台格（诚实声明）

发布只承诺"本表已测格"；未测格不代表不支持，只代表未验证。

## 已测（有证据，见 TEST_RESULTS.md）

| 平台格 | 版本细节 | CLI | GUI | 证据 |
|---|---|---|---|---|
| Windows 7 Ultimate SP1 x64 | build 7601，裸机级 VM | ✅ 全命令矩阵+夹具 | ✅ 视觉验收+自检 | #10 #17 #18 |
| Windows 10/11 x64（开发机 Win10 IoT LTSC 2024 内核 26100） | 管理员 + runas 非提权对照 | ✅ | ✅ 自检 | #7 #15 #19 |
| CentOS 7 x86_64 用户态 | centos7-full 容器（glibc 2.17），静态二进制 | ✅ 全命令矩阵 | 无 GUI | #11 #19 |
| Ubuntu 24.04 (WSL2) | 静态二进制 | ✅ 自检 | 无 GUI | #11 |

## 未测（NOT_TESTED，不宣称支持）

- Windows Server 2008 R2 SP1 x64（无合法镜像，P0 剩余格）
- CentOS 7 内核 3.10 真机（容器为 WSL2 内核，用户态已验）
- Win7 SP1 x86（ADR-001：构建配置保留，首版不打包）
- Windows 8/8.1、Win10 其他 build、其他发行版（Debian/Alpine 等）
- 只读文件系统/ext4 之外的异常输出介质组合

## 已知环境限制

- 深层 SAM / RID 劫持（W11）、WMI 持久化（W10）、内核级 rootkit：**未覆盖**（C 级）
- 包管理器校验（rpm -V / dpkg -V）：未实现适配器（不冒充已检查）
- wtmp/last 二进制、journalctl：未解析（线索以 auth.log/secure 为准）
- 事件日志 Security 通道：需要管理员；受限令牌下如实报 PERMISSION_DENIED
- shell 配置静态解析，不 source 不执行；动态拼接无法求值（报告中说明）
