# ctfir — 先读我（README）

**ctfir** 是离线 CTF 应急响应只读助手：一键扫描 Windows/Linux 主机的账户、计划任务、
服务、自启动、hosts、进程/连接、关键文件哈希、登录日志、webshell 线索等，
输出**中文解释 + 证据原文 + 人工处置建议**的 JSON 与自包含 HTML 报告。

## 三条铁律

1. **只读**：GUI 不修改系统；无修复按钮。CLI `fix` 为可选白名单且需确认。建议仅供复制参考。
2. **离线**：不联网、不下载、不上传；报告零外部资源。
3. **如实**：任何未扫/受限/失败项都在"未完成检查"中列出；PASS 不等于系统安全。

## 快速开始（Windows）

1. 复制整个目录到**目标机本地**（不要在共享盘直接运行）。
2. 核对 `SHA256SUMS`（`certutil -hashfile ctfir.exe SHA256`）。
3. 双击 `ctfir-gui.exe` → 选择输出目录 → 「开始只读扫描」。
   默认视图把账户清单等事实项藏起来，先看「立刻清」；切「全部」找回。
   无管理员权限也能运行：受限模块会如实标注 PERMISSION_DENIED。
4. 打开输出目录中 `report.html`：顶部是处置清单（中文标题 + 一条命令）。
   个人赛/团队赛主机侧都跑全量；Linux 用 `--profile full`。

命令行：`ctfir.exe scan --out C:\ctfir-out`；`ctfir.exe actions --session <目录> --bucket clear`（打印立刻清命令，不执行）；
`ctfir.exe explain --session <目录> --finding <规则ID>`；`ctfir.exe report --session <目录> --redact`。
GUI **没有**修复按钮，也不做 360/SFC 一键系统修复。

## 快速开始（Linux）

```sh
# 拷入 ctfir 后（传输方式按赛事授权）：
chmod u+x ./ctfir && ./ctfir doctor
./ctfir scan --out ./out
# 报告在 ./out/report.html
```

## 搬运提示

- Windows：RDP 剪贴板复制 ZIP（>2GB 不支持）；策略禁用时停止，不绕过。
- Linux：scp 拷入；目标机无需任何运行时（静态二进制）。
- 目标机**不需要**安装 VC/.NET/Python/Node 等任何运行时。

## 卸载

删除本目录与报告输出目录即可。工具不写注册表、不留服务、不留计划任务。
