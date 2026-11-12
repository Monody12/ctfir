# KNOWN_LIMITATIONS — 已知限制（v0.1）

1. **只读工具**：不实现任何修改/修复；报告建议均为人工步骤文本，工具不执行。
2. **PASS ≠ 安全**：PASS 仅表示声明范围内未命中规则；系统整体安全无法由本工具判定。
3. **无内置基线**：关键文件哈希仅留证，需与可信同版本系统/软件包比对；不能据此判定篡改或安全。
4. **未覆盖专题**：WMI 持久化、深层 SAM/RID 劫持、内核 rootkit、内存取证、磁盘镜像模式（见 PLAN §1.4）。
5. **注册表视图**：未加载用户 hive 的 Run 键不覆盖（工具明确标注）；32 位视图仅 Run 键显式扫描。
6. **计划任务 XML**：动作经 COM 读取；损坏 XML 由 COM 层跳过并计数，不做手工解析。
7. **webshell 检测**：静态特征（执行+输入/解码组合），不执行文件、不运行框架；命中≠定罪，需人工读文件+对日志。
8. **JSON 深嵌套**：nlohmann v3.12.0 已含 OSS-Fuzz 修复；本工具仅解析自产 JSON（解析入口只处理本工具写出文件），不解析目标机任意 JSON。
9. **非 UTF-8 文本**（GBK hosts 等）：按原字节保留并标注，规则匹配 ASCII 子串仍有效；payload 显示转义。
10. **性能**：单模块默认预算 30s，超预算如实 TIMEOUT 并列出未覆盖来源；全盘类操作不在范围内。
11. **SAFER 受限令牌**：runas /trustlevel 下 TokenElevation 判定可能仍显示 admin（已知显示偏差），权限不足行为以模块 PERMISSION_DENIED 为准（实测正确）。
12. **签名验证**：WinVerifyTrust 未接入 v0.1（W08 仅哈希留证）；目录签名/catalog 不支持时不得宣称"无签名"。

## v0.6 补充（2026-11-12）

13. **MySQL binlog ROW 格式**：工具只对 STATEMENT/MIXED 明文做关键字扫描（INTO OUTFILE / UDF / LOAD_FILE）。ROW 事件无 SQL 明文时只留证路径并 note，需人工用 `mysqlbinlog` 还原——不把"未命中"写成安全结论。
14. **ADS 扫描范围**：仅当前用户 Desktop/Documents/Downloads、Public、Temp 一层，不递归全盘；Zone.Identifier 等系统良性流明确不报。
15. **PowerShell 历史**：只读 PSReadLine `ConsoleHost_history.txt`（各用户 Roaming 路径）；不写、不改用户历史；Windows PowerShell 5 与 7 的其他历史文件不覆盖。
16. **Web 日志攻击特征**：基于解码后的子串，无业务上下文；命中=线索。curl / python-requests UA 故意不报（运维脚本误报高）。
17. **业务数据恢复**：不在工具范围（决赛指南该项属人工步骤）。动态流量、内存取证、内核 rootkit 仍不覆盖。

## v0.6.1 补充（2026-11-12）

18. **事件通道不由测试清理**：真实服务创建会产生 System 7045 与（若审核开启）Security 4697。夹具在 finally 中删除临服务并复扫确认服务/文件/注册表干净；**禁止** `wevtutil cl` 清空通道。复扫仍可能看到这些事件，属预期，不是清理失败。
19. **PowerShell 历史测试隔离**：自动化用例只读 `CTFIR_FIXTURE_PSHIST` 指向的临时夹具，不读、不改用户真实 `ConsoleHost_history.txt`。生产扫描路径不变（各用户 Roaming）。
20. **平台格替代**：Server 2008 R2 真 OS 与 CentOS 3.10 真内核无法在本开发机用容器启动（见 COMPATIBILITY）。已用合成事件 XML 与 centos:7 用户态夹具做最接近的自动化替代，不把这两格写成 PASSED。

## v0.7.0 补充（2026-11-12）

21. **GUI 仍无写动作**：处置工作台只排序/过滤/展示已填对象的命令，复制到剪贴板。没有修复/执行按钮。
22. **Linux `ctfir fix` 对 persist 仍是注释行**（`linux_comment_line`）。决赛指南要求彻底删除时，按报告里的 `sed -i Nd` / 删行命令手工做，不要把「fix 成功」当成得分。
23. **默认隐藏清单/事实项**（账户全量清单、TASK.FACT、RECENT、用户 Temp 可执行、微软预装 Active Setup CLSID）。检测仍写入 findings.json；视图切「全部」或点 KPI「已隐藏清单」可找回。Web / 日志 / 中间件默认可见。
24. **ADS 清除命令用 `del 文件:流名`**（Win7 无 PowerShell `-Stream`）。Startup 文件夹的 `.vbs/.bat/.js/.exe` 复用 `WIN.AUTORUN.SUSPECT.001`，不是新规则 ID。
25. **不是 360 / 系统急救箱**：不做 SFC、DISM、注册表垃圾清理、驱动修复、系统文件替换。比赛急救路径是 `ctfir scan` → `ctfir actions --bucket clear`（或 GUI「复制命令」）→ 人工粘贴。GUI 永不自动 apply。
26. **Win7 RTM (7600) 与 32 位 x86 未交付**：见 COMPATIBILITY。doctor 的 `compat=warn` 只提示，不阻断扫描。
27. **CI 产物必须用 VS2022（windows-2022）构建**：`windows-latest` 已是 VS18，不再作为 Win7 发布链。

## v0.8.0 补充（2026-11-12）

28. **不是域控查询工具**：不连 LDAP、不枚举 Domain Admins、不读 krbtgt、不解析 ntds.dit 哈希、不解密 GPP cpassword。活 DC 上本地 SAM 仍只含 DC 本机账户（PLAN W01）。
29. **looks_like_dc 是启发式**：SYSVOL 目录存在即视为域控特征（夹具如此）。误把工作站 SYSVOL 残留当 DC 时，Spooler/SMB 签名告警会出现——删掉 SYSVOL 树即消失，不要在工作站关 Spooler。
30. **防火墙发现不自动修复**：`WIN.BASE.FW.OFF.001` 只提示。一键开启可能切断 SSH/RDP。
31. **无真实 Server 2008 R2 DC 真机格**：AD 规则在 Win7 上用文件/注册表模拟验证；活 AD DS 仍 AUTOMATED_SUBSTITUTE。
32. **凭据副本只报路径**：`sam.save` / `ntds.dit` / `lsass.dmp` 只告警文件存在。不解析哈希、不解密 cpassword、不打开 dump。
33. **实验机 Netlogon 原值**：Win7 VM 的 `DisablePasswordChange=1`、`SealSecureChannel=0` 是清理后仍在的实验室原配置，不是夹具残留。不要为消告警去改实验机。

