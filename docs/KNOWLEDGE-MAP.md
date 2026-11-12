# KNOWLEDGE-MAP — CTF 应急考点 ↔ ctfir 规则 ↔ 处置手册映射（复习资料）

> 用法：赛前过一遍本表；比赛时 `ctfir playbook <手册>` 直接查处置步骤。

| 考点（出题习惯） | 规则/模块 | 手册（playbook 参数） | 一句话要点 |
|---|---|---|---|
| 找出后门/隐藏用户 | WIN.ACC.*（INVENTORY/CUSTOM/DOLLAR/LOGIN_HIDE） | user | `$` 账户 API 可见；UserList=0 隐藏；RID>1000 自建 |
| UID0 提权账户 | LNX.ACC.UID0.001 | user | name≠root 但 UID=0 即等价 root |
| 新建账户时间 | WIN.EVT.ACC.CREATE.001（4720） | log | 安全日志直答"何时建的、谁建的" |
| 加管理员组 | WIN.ACC.ADMIN.001 / 4732 | user | SID 判组不靠名字；RID>1000 重点 |
| 计划任务后门 | WIN.TASK.SUSPECT/REFPATH/FACT | task | 动作参数里的路径比主路径更重要；禁用任务也看内容 |
| cron 后门 | LNX.PERSIST.CRON.001 / LNX.AT | cron | 被引用脚本全文必读；互拉守护要一起清 |
| systemd 持久化 | LNX.PERSIST.SYSTEMD/TIMERFACT | cron | ExecStart 与 timer 调度都看 |
| 启动项/注册表 | WIN.AUTORUN.*（Run/Winlogon/IFEO/AppInit/LSA/登录脚本/BootExecute/**Startup 文件夹脚本**） | startup | 主路径+参数路径都提取；`.vbs/.bat` 在 Startup 也会报 |
| 粘滞键后门 | WIN.HASHES（sethc/utilman…） | hash | 与可信同版本比对；IFEO 分支另查 |
| SSH 后门 | LNX.SSH.*（AUTHKEY/PRIVKEY/CONFIG） | sshkey | 指纹逐条核对；forced command 高危 |
| preload/库劫持 | LNX.PERSIST.PRELOAD / LNX.LDSO.INJECT | preload | 配置行+库哈希；不加载不删除先取证 |
| webshell | WIN.WEB.WEBSHELL / LNX.WEB.SHELL | webshell | 静态特征命中≠定罪；隔离先于删除 |
| 攻击者 IP | WIN.WEB.LOGPOST / LNX.WEB.LOGPOST / WIN.EVT.AUTHFAIL / LNX.LOG.AUTHFAIL | log | POST Top IP + 4625/failed Top IP；宝塔走 /www/wwwlogs |
| 攻击者执行了什么 | Prefetch/ShimCache/bash_history/PS 历史/wtmp/lastlog | log | 文件名即程序名；历史是线索非结论 |
| Web 日志攻击溯源 | LNX.WEB.LOGATTACK / WIN.WEB.LOGATTACK | log | URL SQLi、../ 穿越、webshell 文件访问、sqlmap 等 UA（含百分号解码） |
| 服务安装后门时间 | WIN.EVT.SVC7045（System 7045 + Security 4697） | service | 时间即植入时间；与 WIN.SVC 当前配置互补 |
| NTFS 隐藏文件 | WIN.FILES.ADS | hash | dir /r 或 FindFirstStreamW；忽略 Zone.Identifier |
| SSH 密码记录后门 | LNX.PERSIST.SSHLOG（/tmp/.sshlog） | sshkey | PAM 后门产物；只报路径不入库口令 |
| 数据库日志写马 | MID.MYSQL.LOGSHELL / SLOWLOG / BINLOG | webshell | general/slow 明文；binlog ROW 需人工 mysqlbinlog |
| U 盘取证 | WIN.USB（USBSTOR） | log | 配合 setupapi.dev.log 看时间 |
| 哈希比对/文件篡改 | --baseline + WIN.FILES.BASELINE / LNX.FILES.BASELINE | hash | 自带基线清单文件即可判定 |
| 服务后门 | WIN.SVC.SUSPECT / WIN.DRV.WRITABLE | service | 可写路径+未引号+签名三看 |
| 提权痕迹 | LNX.SUID.UNEXPECTED / LNX.CAPS | user | 白名单外即人工核实 |
| 弱口令爆破 | 4625 Top IP / secure Failed | log | 时间窗内集中失败 |
| 处置后复查 | ctfir diff --a 处置前 --b 处置后 | — | resolved=已清除 added=新出现 |
| 本机是不是域控 | WIN.AD.ROLE.001 | ad | ProductType：WinNT 工作站 / ServerNT 成员 / LanmanNT 域控；本地 SAM ≠ Domain Admins |
| GPP cpassword | WIN.AD.GPP.CPASSWORD.001 | ad | SYSVOL XML 含 cpassword；删文件并轮换口令，工具不落明文 |
| GPP 加本地管理员 / Registry / Files / Services | WIN.AD.GPP.ADMIN / REG / FILE / SVC | ad | 删 XML；Files 投放与 Services 改服务都是域持久化 |
| ntds.dit 副本 / IFM | WIN.AD.NTDS.COPY / IFM | ad | 只报文件；活库 `Windows\NTDS\ntds.dit` 不告警 |
| SAM/SYSTEM.save / lsass.dmp | WIN.AD.HIVE.COPY / LSASS.DMP | ad | `reg save` 与 MiniDump 残留；不解析哈希 |
| SYSVOL 登录脚本 / GPO 立即任务 | WIN.AD.SYSVOL.SCRIPT / GPO.TASK / SCRIPTINI | ad | 域用户可读，gpupdate 后全域执行 |
| GPO 委派特权 | WIN.AD.GPO.DELEG.001 | ad | GptTmpl.inf SeEnableDelegationPrivilege 多出来的 SID |
| DSRM 在线登录 / LDAP 不签名 / 通道绑定 | WIN.AD.DSRM / LDAP.NOSIGN / LDAP.BIND | harden | 改回 0 / Integrity=2 / Binding=2 |
| 域控 Spooler / SMB 签名 | WIN.AD.SPOOLER.DC / SMBSIGN | harden | 仅 looks_like_dc（SYSVOL/NTDS/LanmanNT）才报 |
| 机器账户密码 / 安全通道 | WIN.AD.MACHPWD / WIN.BASE.SEALCHAN | harden | DisablePasswordChange=0；Seal=1 |
| WDigest / NTLMv1 / PTH | WIN.BASE.WDIGEST / NTLMV1 / LATFP | harden | UseLogonCredential=0；LmCompatibilityLevel=5；LATFP=0 |
| 匿名 SAM / Everyone 匿名 / SMB 明文 / 来宾模型 | WIN.BASE.RESTRICTANON / EVERYONEANON / PLAINSMB / FORCEGUEST | harden | 技能赛模块 A 高频 |
| PrintNightmare PointAndPrint / AlwaysInstallElevated / WinRM 明文 | WIN.BASE.PNP.ELEV / ALWAYSINST / WINRM.UNENC | harden | 注册表回 0 |
| RDP 加密 / SecurityLayer / RemoteRegistry | WIN.BASE.RDP.ENCRYPT / RDP.SECLAYER / REMOTEREG | harden | MinEncryptionLevel=3；SecurityLayer=2；服务禁用 |
| 密码历史 / 永不过期 / 显示上次用户名 / 防火墙关 | WIN.BASE.PWDHIST / PWDAGE / LASTUSER / FW.OFF | harden | 防火墙不自动开（防切断 SSH） |
| Domain Admins / krbtgt / DCSync / 委派 / ADCS / 黄金票 | — | ad | **C 级**：需 LDAP/事件/内存；`ctfir playbook ad` 写了手工命令 |

完整对照见 [AD-SERVER-POINTS.md](AD-SERVER-POINTS.md)。

**三不变**：工具只读；PASS≠安全；未完成检查如实列出。
