# Windows Server / AD 域控考点全表（v0.8）

对照来源：经纬杯决赛指南（主机应急）、全国技能大赛模块 A 加固样题、玄机/CTF Windows Server 应急、MITRE AD 凭据与持久化。
授权实验机是 **Win7 Ultimate SP1 工作站**，不能升级成 DC。能在该机验证的是「文件/注册表模拟」；需要活 LDAP 的项标 **C（未覆盖）**。

角色约定：`ProductType` WinNT=工作站、ServerNT=成员服务器、LanmanNT=域控。本地 SAM ≠ 域账户（PLAN W01）。

## A. 成员服务器 / 工作站上仍然有效（原 142 点的 Windows 子集）

账户、Guest、隐藏登录、计划任务、服务、Run/IFEO/Winlogon、hosts、portproxy、共享、IIS webshell/日志、RDP NLA、SMBv1、UAC、空口令网络登录、默认共享、自动登录、审核关闭、WMI、工具残留、远控软件。

**结论：把工具拷到 Windows Server 2008 R2 / 2012 成员服务器上，上述规则照常工作。** 不是「只认 Win7」。

## B. 技能赛模块 A 加固（截图给分，工具给差距）

| # | 考点 | 规则 | 状态 |
|---|---|---|---|
| 1 | 密码最小长度 | WIN.BASE.PWDLEN.001 | 已有 |
| 2 | 账户锁定阈值 | WIN.BASE.LOCKOUT.001 | 已有 |
| 3 | 密码历史 | WIN.BASE.PWDHIST.001 | v0.8 |
| 4 | 密码永不过期 | WIN.BASE.PWDAGE.001 | v0.8 |
| 5 | 密码复杂度 | — | **C**（复杂度在 SAM 二进制/secedit，只读不解析 SAM） |
| 6 | Guest 禁用 | WIN.BASE.GUEST.001 | 已有 |
| 7 | Guest 不在管理员 | WIN.ACC.GUESTADMIN.001 | 已有 |
| 8 | 不显示上次用户名 | WIN.BASE.LASTUSER.001 | v0.8 |
| 9 | 匿名枚举 SAM | WIN.BASE.RESTRICTANON.001 | v0.8 |
| 10 | Everyone 含匿名 | WIN.BASE.EVERYONEANON.001 | v0.8 |
| 11 | SMB 明文口令 | WIN.BASE.PLAINSMB.001 | v0.8 |
| 12 | 登录横幅 LegalNotice | — | 默认空，报了会全机误报；手册人工 |
| 13 | 关机清页面文件 | — | 同上默认 0 |
| 14 | 未登录关机 | — | secedit 权限，C |
| 15 | 取得所有权只给 Admins | — | secedit，C |
| 16 | 禁止普通用户 cmd | — | HKCU 策略，C |
| 17 | RDP NLA | WIN.BASE.RDP.NONLA.001 | 已有 |
| 18 | RDP 空闲超时 | — | 缺省即无超时，报了全机误报 |
| 19 | 审核登录 | WIN.AUDIT.DISABLED.001 | 已有 |
| 20 | 事件日志大小 | WIN.BASE.LOGRET.001 | 部分（Retention） |
| 21 | IIS 日志 | WIN.WEB.LOGPOST/LOGATTACK | 有 IIS 才扫 |
| 22 | SMBv1 | WIN.BASE.SMB1.001 | 已有 |
| 23 | UAC | WIN.BASE.UAC.001 | 已有 |
| 24 | 空口令网络登录 | WIN.BASE.BLANKPWD.001 | 已有 |
| 25 | 默认管理共享 | WIN.BASE.DEFSHARE.001 | 已有 |
| 26 | 防火墙开启 | WIN.BASE.FW.OFF.001 | v0.8（不自动开启，以免切断 SSH） |
| 27 | 超过登录时间强制注销 | WIN.BASE.FORCELOGOFF.001 | v0.8 |
| 28 | 禁止网络来宾模型 | WIN.BASE.FORCEGUEST.001 | v0.8 |
| 29 | RDP 加密级别 High | WIN.BASE.RDP.ENCRYPT.001 | v0.8；缺键不报 |
| 30 | Remote Registry 非自动 | WIN.BASE.REMOTEREG.001 | v0.8；仅 AUTO 报 |
| 31 | UAC 管理员提示 | WIN.BASE.UAC.NOPROMPT.001 | v0.8 |
| 32 | Ctrl+Alt+Del 登录注意 | WIN.BASE.DISABLECAD.001 | v0.8 |
| 33 | 装域 / 建 OU / 用户组 / GPO 链接 | — | **C** 配置任务，不是应急扫描 |
| 34 | 密码复杂度 / LegalNotice / 清页面文件 / 未登录关机 | — | 默认值全机误报或需解析 SAM，手册人工 |

## C. CTF 应急 · 域控文件与凭据防护（v0.8 可识别，Win7 可种夹具）

| # | 考点 | 规则 | 修复口径 |
|---|---|---|---|
| 28 | GPP cpassword（Groups/Services/Tasks XML） | WIN.AD.GPP.CPASSWORD.001 | 删 XML，轮换被写入账户；**不解出口令入库** |
| 29 | ntds.dit 副本（Temp/用户目录） | WIN.AD.NTDS.COPY.001 | 隔离副本；确认泄露则两次重置 krbtgt |
| 30 | ntdsutil IFM 目录 | WIN.AD.IFM.001 | 删 IFM 树 |
| 31 | 活动 `C:\Windows\NTDS\ntds.dit` | 只 note | 域控正常文件，不当副本 |
| 32 | SYSVOL/NETLOGON 登录脚本 | WIN.AD.SYSVOL.SCRIPT.001 | 删脚本 |
| 33 | GPO 立即任务 ScheduledTasks.xml | WIN.AD.GPO.TASK.001 | 删 XML |
| 34 | GPO scripts.ini CmdLine | WIN.AD.GPO.SCRIPTINI.001 | 删/清空 CmdLine |
| 35 | GptTmpl.inf 委派特权扩大 | WIN.AD.GPO.DELEG.001 | 只留 Administrators |
| 36 | DSRM 在线登录 | WIN.AD.DSRM.LOGON.001 | DWORD=0 |
| 37 | LDAP 不签名 | WIN.AD.LDAP.NOSIGN.001 | LDAPServerIntegrity=2 |
| 38 | 域控上 Spooler（PrintNightmare） | WIN.AD.SPOOLER.DC.001 | 仅 looks_like_dc 时；停服务 |
| 39 | 域控未强制 SMB 签名 | WIN.AD.SMBSIGN.001 | RequireSecuritySignature=1 |
| 40 | WDigest 明文 | WIN.BASE.WDIGEST.001 | UseLogonCredential=0 |
| 41 | NTLMv1/LM | WIN.BASE.NTLMV1.001 | LmCompatibilityLevel=5 |
| 42 | PTH 过滤器 | WIN.BASE.LATFP.001 | LocalAccountTokenFilterPolicy=0 |
| 43 | 存储 LM 哈希 | WIN.BASE.NOLMHASH.001 | NoLmHash=1 |
| 44 | PointAndPrint 免提权 | WIN.BASE.PNP.ELEV.001 | 改 0 |
| 45 | AlwaysInstallElevated | WIN.BASE.ALWAYSINST.001 | HKLM+HKCU=0 |
| 46 | WinRM 明文/Basic | WIN.BASE.WINRM.UNENC.001 | 关 AllowUnencrypted/AllowBasic |
| 47 | 角色说明 | WIN.AD.ROLE.001 | 清单，不修 |
| 48 | GPP 加本地管理员 | WIN.AD.GPP.ADMIN.001 | 删 Groups.xml 并撤管理员 |
| 49 | GPP Registry.xml | WIN.AD.GPP.REG.001 | 删 XML |
| 50 | GPP Files/Shortcuts.xml | WIN.AD.GPP.FILE.001 | 删 XML 并清投放文件 |
| 51 | GPP Services.xml | WIN.AD.GPP.SVC.001 | 删 XML；常与 cpassword 同现 |
| 52 | LDAP 通道绑定关闭 | WIN.AD.LDAP.BIND.001 | LdapEnforceChannelBinding=2 |
| 53 | 计算机账户密码不再更换 | WIN.AD.MACHPWD.001 | DisablePasswordChange=0 |
| 54 | SAM/SYSTEM/SECURITY 副本 | WIN.AD.HIVE.COPY.001 | 隔离 sam.save 等；不解析哈希 |
| 55 | lsass.dmp | WIN.AD.LSASS.DMP.001 | 隔离删除 |
| 56 | 安全通道未加密 | WIN.BASE.SEALCHAN.001 | Seal/RequireSignOrSeal=1 |
| 57 | LDAP 客户端不签名 | WIN.BASE.LDAPCLIENT.001 | LDAPClientIntegrity=2 |
| 58 | 非管理员装打印驱动 | WIN.BASE.PNP.ADMIN.001 | RestrictDriverInstallationToAdministrators=1 |
| 59 | RDP SecurityLayer=0 | WIN.BASE.RDP.SECLAYER.001 | 改 2 |
| 60 | 缓存域登录过大 | WIN.BASE.CACHEDLOGON.001 | CachedLogonsCount=10 |
| 61 | NTLM 会话安全 0 | WIN.BASE.NTLMSEC.001 | 0x20080000 |
| 62 | PowerShell Unrestricted | WIN.BASE.PS.UNRESTRICT.001 | Restricted |

## D. 必须活 DC / LDAP / 内存，本工具明确不覆盖（C）

| # | 考点 | 为何没有 | 比赛怎么办 |
|---|---|---|---|
| 63 | 额外 Domain Admins / Enterprise Admins | 不查询 LDAP；本地 SAM 看不到域组 | `net group "Domain Admins" /domain` |
| 64 | krbtgt 密码年龄 / 黄金票据 | 需 AD 与 4769 | 事件查看器 + 两次重置 krbtgt |
| 65 | DCSync ACL（Replicating Directory Changes） | LDAP ACL | ADSI Edit / 4662 |
| 66 | 非约束委派 userAccountControl | LDAP | `Get-ADComputer -Filter {TrustedForDelegation -eq $true}` |
| 67 | AdminSDHolder / SDProp | LDAP | ADUC 高级安全 |
| 68 | SID History | LDAP | |
| 69 | Kerberoasting SPN / AS-REP | LDAP | |
| 70 | ADCS ESC1–ESC8 / PetitPotam 完整链 | 需 CA | Spooler 项是缓解面 |
| 71 | ZeroLogon / 骨架密钥 / DCShadow | 补丁/内存 | |
| 72 | 活 NTDS 哈希导出 | **红线禁止** | 只报副本文件 |
| 73 | dcdiag / DFSR / 信任关系 | 需 DC 健康 API | |
| 74 | LAPS / gMSA / Protected Users | LDAP | |
| 75 | 建域、中间 CA、加域 | 配置赛不是应急扫描 | |

## E. 经纬杯现场判断

个人赛 3 小时主机题：高概率仍是 Win7/2008R2 **单机**持久化 + IIS，用 A 类即可。
团队赛若给一台 Server 域控镜像：A+C 类能直接打 GPP/NTDS 副本/GPO 脚本/凭据防护；D 类必须手工 LDAP/事件，报告里 `ctfir playbook ad` 已写明边界。

Win7 实验机验证方法：`tests/practice/ad-server/install.cmd` 种 SYSVOL/NTDS 模拟物 + 注册表，不把机器变成 DC，测后 `cleanup.cmd`。JW2026-WIN7-01 不动。
