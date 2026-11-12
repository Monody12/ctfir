# DETECTION-POINTS — 检测点全表 v0.8（用例需求的唯一来源）

来源约定：`[A=T1053.005]` = MITRE ATT&CK；`[AR]`=Autoruns 覆盖位置清单；`[LY]`=Lynis/GScan 检查项类；`[CTF]`=ctfshow 应急题面考点。每个检测点 ↔ 规则 ID ↔ 用例行（tests/cases/*.tsv）。
用例纪律：每点最少 1 正例 + 2 负例 + 3 变体；负例语料 = 四环境干净扫描 explained-findings.tsv。

## Windows（60 点）

| # | 检测点 | 来源 | 规则 ID | 正例设计 | 负例/变体 |
|---|---|---|---|---|---|
| 1 | 新建本地账户 | [A=T1136.001][AR] | WIN.ACC.CUSTOM.001 | net user ctfir-marker（RID>1000） | 内置 500/501 不报；disabled 账户仍报（事实） |
| 2 | 账户全量清单 | [LY][CTF] | WIN.ACC.INVENTORY.001 | 任意机器 info 级 | — |
| 3 | $ 结尾账户 | [CTF] | WIN.ACC.DOLLAR.001 | net user h$ /add | SUPPORT_xxxx 机器账户跳过 |
| 4 | 管理员组成员(RID>1000) | [A=T1098][CTF] | WIN.ACC.ADMIN.001 | 加入 Administrators | 内置 500 不报 |
| 5 | 登录界面隐藏 **=0** | [A=T1562][CTF] | WIN.ACC.LOGIN_HIDE.001 | UserList DWORD 0（A7C9-W02） | 值=1 不报；值类型 SZ 不报 |
| 6 | hosts 非默认映射 | [CTF] | WIN.HOSTS.MAP.001 | 10.x → 域名 | localhost/ip6- 跳过 |
| 7 | hosts 回环绑陌生名 | [CTF] | WIN.HOSTS.LOOPBACK.001 | 127.0.0.1 ctf-test.invalid（A7C9-W05） | 127.0.0.1 localhost 跳过 |
| 8 | hosts 0.0.0.0 沉坑聚合 | [CTF] | （note 聚合） | 屏蔽列表 | — |
| 9 | Run 键网络/解释器特征 | [A=T1547.001][AR] | WIN.AUTORUN.SUSPECT.001 | powershell -enc | OneDrive 等系统路径不进此规则 |
| 10 | Run 键指向可写目录 | [AR][CTF] | WIN.AUTORUN.WRITABLE.001 | Temp\marker.exe | Program Files 不报 |
| 11 | Run 键参数引用非常规路径 | [A7C9-W03] | WIN.AUTORUN.REFPATH.001 | cmd /c ""C:\CTF-Test\harmless.cmd"" | 仅 System32 引用不报 |
| 12 | Winlogon Shell/Userinit 异常 | [A=T1547.004][AR] | WIN.AUTORUN.WINLOGON.001 | explorer.exe 后附加 | 默认值不报 |
| 13 | UserInitMprLogonScript | [A=T1037][AR] | WIN.AUTORUN.LOGONSCRIPT.001 | 设置登录脚本值 | 空值不报 |
| 14 | BootExecute 非默认 | [A=T1069?][AR] | WIN.AUTORUN.BOOTEXECUTE.001 | 改写 | autocheck autochk * 不报 |
| 15 | AppInit_DLLs 非空 | [A=T1546.010][AR] | WIN.AUTORUN.APPINIT.001 | 写入 dll 路径 | 空/0 不报 |
| 16 | IFEO Debugger | [A=T1546.012][AR][CTF] | WIN.AUTORUN.IFEO.001 | sethc.exe Debugger | 无 Debugger 值子键不报 |
| 17 | LSA 包注入 | [A=T1547?][AR] | WIN.AUTORUN.LSA.001 | Security Packages 附加 | 默认 msv1_0 等不报 |
| 18 | Startup 文件夹 | [A=T1547.007][AR] | （证据+路径规则） | 放 .vbs | 空 |
| 19 | 系统服务可疑路径 | [A=T1543.003][AR][CTF] | WIN.SVC.SUSPECT.001 | binPath→Temp | 系统服务不报 |
| 20 | 服务路径未加引号 | [CTF] | WIN.SVC.UNQUOTED.001 | Program Files 子目录带空格 | 已引号不报 |
| 21 | 驱动可写路径 | [A=T1543.003] | WIN.DRV.WRITABLE.001 | sys 落 Temp | 系统驱动不报 |
| 22 | 计划任务可疑动作 | [A=T1053.005][CTF] | WIN.TASK.SUSPECT.001 | 任务→Temp+certutil | 系统任务不报 |
| 23 | 任务引用非常规路径 | [A7C9-W04] | WIN.TASK.REFPATH.001 | 动作引外部 cmd | System32 引用不报 |
| 24 | 任务事实化（含禁用） | [A7C9-W04] | WIN.TASK.FACT.001 | 禁用任务 2099 | \Microsoft\ 不报 |
| 25 | 隐藏+启用任务 | [A=T1053.005] | （SUSPECT 标注） | Hidden+Ready | 系统隐藏任务不报 |
| 26 | 4720 创建账户事件 | [A=T1136.001][CTF] | WIN.EVT.ACC.CREATE.001 | net user /add（真实事件） | 无事件不报 |
| 27 | 4722/24/25/26/4732 时间线 | [A=T1136][CTF] | WIN.EVT.ACC.TIMELINE.001 | 入管理员组 4732 | — |
| 28 | 4625 爆破 Top IP | [CTF] | WIN.EVT.AUTHFAIL.001 | ≥20 次失败 | 少量失败不报 |
| 29 | 进程 cmdline 矿池 | [A=T1496][CTF] | WIN.PROC.CMDLINE.001 | stratum+tcp 进程 | 正常进程不报 |
| 30 | 进程 cmdline 隐藏执行 | [A=T1059.001][CTF] | WIN.PROC.CMDLINE.001 | powershell -w hidden -enc | 正常 PS 不报 |
| 31 | 端口↔进程关联 | [E07][CTF] | （PROCNET+PROCCMD 证据） | netstat 可核对 | — |
| 32 | 双扩展名伪装 | [A7C9-W08][CTF] | WIN.FILES.DOUBLEEXT.001 | invoice.pdf.exe | .tar.gz/版本号 .3-1 不报 |
| 33 | 临时目录可执行 | [CTF] | WIN.FILES.TEMPEXE.001 | Temp\x.exe | — |
| 34 | 自定义基线 mismatch | [A7C9-W06] | WIN.FILES.BASELINE.001 | 改文件+--baseline | 内容一致不报 |
| 35 | 基线文件缺失 | [CTF] | WIN.FILES.BASELINE.MISS.001 | 删清单文件 | — |
| 36 | Prefetch 可疑程序 | [A=T1124?] | WIN.TRACE.PREFETCH.001 | miner.pf | 正常程序不报 |
| 37 | ShimCache 执行痕迹 | [AR] | （启发式证据） | 缓存含路径 | — |
| 38 | U 盘接入痕迹 | [CTF] | （WIN.USB 证据） | USBSTOR 子键 | — |
| 39 | RDP 连接 MRU | [CTF] | （RDPMRU 证据） | Servers 子键 | — |
| 40 | 防火墙放行可写程序 | [LY] | WIN.FW.WRITABLEAPP.001 | 规则 app→Temp | 系统程序不报 |
| 41 | 非默认共享 | [A=T1021?][CTF] | WIN.SHARE.NONDEFAULT.001 | net share 自建 | admin$ 跳过 |
| 42 | webshell 静态特征 | [A=T1505.003][CTF] | WIN.WEB.WEBSHELL.001 | eval+$_POST 一句话 | 框架文件需白名单人工 |
| 43 | IIS 日志 POST Top IP | [CTF] | WIN.WEB.LOGPOST.001 | 攻击日志样本 | 无 POST 不报 |
| 44 | 关键二进制哈希留证 | [LY] | （HASHES 证据） | sethc 等 12 文件 | 无基线不判篡改 |
| 45 | 事件时间线（4624） | [CTF] | （EVTLOG 证据） | — | — |
| 46–60 | 变体矩阵：GBK hosts / CRLF / 大小写 / 引号嵌套 / 长值截断 / 拒绝访问路径 / 未加载 hive / 32 位视图 / 空 XML / 超长行 / 双视图一致性 / 值类型混淆 / Task XML CDATA / 服务描述伪装 / Prefetch 清理提示 | 本表 | 各规则 | 变体用例 | 用例库 cases_win.tsv |

## Linux（40 点）

| # | 检测点 | 来源 | 规则 ID | 正例设计 | 负例/变体 |
|---|---|---|---|---|---|
| 61 | 非 root UID0 | [CTF][LY] | LNX.ACC.UID0.001 | passwd 追加 | 仅 root 不报 |
| 62 | 重复 UID | [LY] | LNX.ACC.DUPUID.001 | 共享 0/1000 | 单账户不报 |
| 63 | GID0 非 root 成员 | [LY] | LNX.ACC.GID0.001 | group 追加 | 仅 root 不报 |
| 64 | sudoers NOPASSWD ALL | [LY] | LNX.ACC.SUDOERS.001 | sudoers.d 注入 | 带注释行不报 |
| 65 | shadow 全局可读 | [LY][CIS] | LNX.ACC.SHADOWPERM.001 | chmod o+r | 0640 shadow 组惯例 low |
| 66 | authorized_keys 清单 | [A=T1098?][CTF] | LNX.SSH.AUTHKEY.001 | 注入公钥 | 无文件不报 |
| 67 | forced command key | [CTF] | （AUTHKEY 升级 medium） | command= 选项 | 普通选项不升级 |
| 68 | 异常私钥存在 | [CTF] | LNX.SSH.PRIVKEY.001 | 放置 id_rsa | 无 |
| 69 | PermitRootLogin yes | [LY] | LNX.SSH.CONFIG.001 | sshd_config | 注释行不报 |
| 70 | AuthorizedKeysFile 改道 | [CTF] | （note） | 自定义路径 | 默认不提示 |
| 71 | cron 可写路径/矿池 | [A=T1053.003][CTF] | LNX.PERSIST.CRON.001 | /tmp+curl | 备份任务需人工（low→medium 分级） |
| 72 | at 队列可疑 | [A=T1053.003] | LNX.PERSIST.AT.001 | at 任务注入 | 空 |
| 73 | systemd unit Exec 可疑 | [A=T1543.002][CTF] | LNX.PERSIST.SYSTEMD.001 | ExecStart=/tmp | 系统 unit 不报 |
| 74 | systemd timer 事实 | [A=T1053.002] | LNX.TIMER.FACT.001 | 自建 .timer | vendor 不报 |
| 75 | rc.local 可疑 | [AR] | LNX.PERSIST.RCLOCAL.001 | 注入行 | 注释行不报 |
| 76 | ld.so.preload 非空 | [A=T1574.006][CTF] | LNX.PERSIST.PRELOAD.001 | 写入 .so | 空文件不报 |
| 77 | ld.so.conf.d 注入 | [A=T1574.006] | LNX.LDSO.INJECT.001 | 非 /usr 路径 | 标准路径不报 |
| 78 | profile/bashrc 可疑 | [A=T1546?] | LNX.PERSIST.PROFILE.001 | alias+curl | 普通别名不报 |
| 79 | bash_history 可疑命令 | [CTF] | LNX.TRACE.HISTORY.001 | wget/chmod 777 | 正常命令不报 |
| 80 | 内核模块清单 | [LY] | （LNX.TRACE 证据） | — | 无基线不判 |
| 81 | 进程 deleted exe | [CTF] | LNX.PROC.DELETED.001 | 运行中删除 | 升级期正常说明 |
| 82 | 进程矿池特征 | [A=T1496] | LNX.PROC.MINER.001 | stratum cmdline | — |
| 83 | SUID 意外清单 | [LY][CTF] | LNX.SUID.UNEXPECTED.001 | /usr/bin/marker 4755 | usernetctl 等发行版白名单 |
| 84 | capabilities 非常规 | [LY] | LNX.CAPS.UNEXPECTED.001 | setcap marker | ping/mtr 白名单 |
| 85 | auth 日志爆破 Top IP | [CTF] | LNX.LOG.AUTHFAIL.001 | ≥20 失败 | 少量不报 |
| 86 | lastlog/wtmp 登录时间线 | [CTF] | （LOGINS 证据） | 真实登录 | 空 |
| 87 | Linux webshell | [A=T1505.003][CTF] | LNX.WEB.SHELL.001 | /var/www 落地一句话 | 框架文件人工 |
| 88 | web access POST Top IP | [CTF] | LNX.WEB.LOGPOST.001 | httpd 日志样本 | 无 |
| 89 | nginx/apache root 定位 | [CTF] | （WEB 证据） | conf root 指令 | — |
| 90–100 | 变体矩阵：CRLF/GBK/UTF-16 hosts、passwd 字段缺列、crontab 环境行、spool 权限拒绝、hidepid、xfs/ext4、超大 history、软链 /etc、cron.d 大小写、at 队列 old 格式 | 本表 | 各规则 | 变体用例 | cases_linux.tsv |
| 101 | 系统命令被替换（假 ls/ps） | [CTF][A=T1036] | LNX.BASE.CMDSIZE.001 | 脚本替换 /usr/bin/ls | 大小阈值为统计值，需 rpm -Va 复核 |
| 102 | SSH 非默认端口 | [CTF] | LNX.SSH.PORT.001 | sshd_config Port 2222 | 22 静默不报 |
| 103 | 近期新增/修改可执行文件 | [CTF] | LNX.BASE.RECENT.001 | /root 7 天内 .sh | mtime 线索级 low |
| 104 | 进程名与 exe 伪装 | [CTF][A=T1036] | LNX.PROC.NAMEMISMATCH.001 | exec -a kworkerd 假进程 | 解释器/busybox 白名单 |
| 105 | netsh portproxy 转发后门 | [CTF][A=T1090] | WIN.PORTPROXY.001 | v4tov4 13389→外部 | 无规则静默 |
| 106 | Windows 近期可执行文件 | [CTF] | WIN.FILES.RECENT.001 | 7 天内 mtime exe | 线索级 low |
| 107 | MySQL 日志写马取证 | [CTF][决赛指南] | MID.MYSQL.LOGSHELL.001 | general_log INTO OUTFILE | 仅核对 ≤3 个日志文件 |
| 108 | web 根敏感凭据泄露 | [决赛指南·密钥治理] | MID.WEB.CREDS.001 | .env/.pem/.key/id_rsa | — |
| 109 | web 根 .git 源码泄露 | [CTF] | MID.WEB.GITLEAK.001 | .git 目录 | — |
| 110 | 中间件未降权运行 | [决赛指南·降权] | LNX.BASE.DROPRIGHT.001 | mysqld root 运行 | nginx/httpd master-root 属标准架构不报 |
| 111 | SELinux 非强制模式 | [决赛指南·安全模块] | LNX.BASE.SELINUX.001 | SELINUX=disabled | enforcing 静默；容器无 SELinux 走 note |
| 112 | AppArmor 无 profile | [决赛指南·安全模块] | LNX.BASE.APPARMOR.001 | 模块启用但无加载 | note 级 |
| 113 | PAM 后门 | [玄机][A=T1543?] | LNX.PERSIST.PAM.001 | pam_exec.so /tmp | 标准 /lib security 路径不报 |
| 114 | umask 过宽 | [等保] | LNX.BASE.UMASK.001 | umask 022 | ≥027 静默 |
| 115 | 登录失败未锁定 | [等保] | LNX.BASE.FAILLOCK.001 | 无 pam_faillock | 有即静默 |
| 116 | 会话无 TMOUT | [等保] | LNX.BASE.TMOUT.001 | /etc/profile 无 TMOUT | 有即静默 |
| 117 | sshd 允许口令登录 | [等保] | LNX.SSH.PWDAUTH.001 | PasswordAuthentication yes | no 静默 |
| 118 | sshd MaxAuthTries 过大 | [等保] | LNX.SSH.MAXAUTH.001 | >6 | ≤6 静默 |
| 119 | Linux 勒索痕迹 | [玄机] | LNX.RANSOM.TRACE/SCRIPT.001 | 勒索信/加密扩展名 | 置信 low |
| 120 | UAC 禁用 | [等保] | WIN.BASE.UAC.001 | EnableLUA=0 | 1 静默 |
| 121 | 空口令可网络登录 | [等保] | WIN.BASE.BLANKPWD.001 | LimitBlankPasswordUse=0 | 1 静默 |
| 122 | 默认共享未禁 | [等保] | WIN.BASE.DEFSHARE.001 | AutoShareWks 开 | 显式 0 静默 |
| 123 | 审核子类关闭 | [等保][玄机] | WIN.AUDIT.DISABLED.001 | auditpol No Auditing | 全开静默 |
| 124 | Windows 勒索痕迹 | [玄机] | WIN.RANSOM.TRACE/WALLPAPER.001 | 勒索信/壁纸篡改 | Themes 白名单 |
| 125 | MySQL UDF 提权 | [玄机·MySQL题] | MID.MYSQL.UDF.001 | plugin_dir/udf.so | 自定义 .so 走 note |
| 126 | MySQL error.log 反弹shell | [玄机] | MID.MYSQL.ERRSHELL.001 | bash -i/dev/tcp | — |
| 127 | web 黑链/黑页 | [玄机·黑链章] | LNX.WEB.BLACKLINK.001 + WIN.WEB.BLACKLINK.001 | 隐藏样式+外链 | — |
| 128 | 攻击工具遗留 | [玄机×4][知攻×2] | LNX.TOOLS.* / WIN.TOOLS.ARTIFACT/FRPCFG | fscan/frp/nps/ew | 文件名+frp配置特征 |
| 129 | .ssh 点开头隐藏密钥 | [玄机·行业攻防] | LNX.SSH.HIDDENKEY.001 | /root/.ssh/.id_rsa.pub | — |
| 130 | Guest 入管理员组 | [知攻·克隆账号] | WIN.ACC.GUESTADMIN.001 | Guest RID501 in Admins | — |
| 131 | 用户改名事件 | [玄机·evtx] | （W09 4781 时间线） | Administrator→Administratro | — |
| 132 | 远控软件痕迹 | [玄机·向日葵题] | WIN.RMT.SOFTWARE/RCE.001 | SunLogin/ToDesk 等 | 未装静默；RCE 走日志特征 |
| 133 | 服务创建事件 7045/4697 | [玄机·权限维持 MysqlServer] | WIN.EVT.SVC7045.001 | System 7045 可写路径/解释器/Mysql 伪装名；Security 4697 成对 | 系统目录合法服务不报；7045 不在 Security 通道（已改查 4697） |
| 134 | PowerShell 历史取证 | [玄机][CTF] | WIN.TRACE.PSHIST.001 | PSReadLine ConsoleHost_history.txt 含 -enc/IEX/DownloadString | 普通 Get-ChildItem / 单独 whoami 不报 |
| 135 | NTFS ADS 隐藏流 | [CTF][AR] | WIN.FILES.ADS.001 | Desktop/Documents/Downloads/Public/Temp 命名流 :hidden.exe | Zone.Identifier / favicon / 主数据流 ::$DATA 不报 |
| 136 | SSH 明文口令记录后门 | [玄机·Linux后门应急 /tmp/.sshlog] | LNX.PERSIST.SSHLOG.001 | /tmp/.sshlog 等 PAM 落点 | 无文件不报；同路径不双计；口令正文不入库 |
| 137 | 宝塔 wwwlogs 访问日志 | [玄机·宝塔题] | LNX.WEB.LOGPOST.001（路径扩展） | /www/wwwlogs/{site}.log POST Top IP | 仅 access.log 文件名会漏检（已修）；.error.log 跳过 |
| 138 | Web 日志 GET 攻击特征（Linux） | [决赛指南·日志审计] | LNX.WEB.LOGATTACK.001 | URL SQLi / ../ 穿越 / webshell 文件名 / sqlmap UA（含编码） | 普通 GET、业务词 union、curl UA 不报 |
| 139 | Web 日志 GET 攻击特征（Windows） | [决赛指南·日志审计] | WIN.WEB.LOGATTACK.001 | IIS W3C + phpstudy/xampp/wamp combined 同口径 | 同上负例 |
| 140 | MySQL slow log 写马/UDF | [决赛指南·数据库日志] | MID.MYSQL.SLOWLOG.001 | slow 日志 INTO OUTFILE / CREATE FUNCTION | 普通 SELECT 不报 |
| 141 | MySQL binlog 明文取证 | [决赛指南·数据库日志] | MID.MYSQL.BINLOG.001 | STATEMENT 明文 CREATE FUNCTION / OUTFILE | ROW 格式无明文：只留证路径，需 mysqlbinlog 人工（如实 note） |
| 142 | 编码变体（双重 URL 编码 / %2f 穿越） | 本表 | LOGATTACK 变体 | %2520UNION%2520SELECT、..%2f | 用例覆盖 |

| 143 | 密码历史为 0 | [技能赛] | WIN.BASE.PWDHIST.001 | uniquepw=0 | ≥5 静默 |
| 144 | 密码永不过期 | [技能赛] | WIN.BASE.PWDAGE.001 | maxpwage=unlimited | 有期限静默 |
| 145 | 显示上次登录用户名 | [技能赛] | WIN.BASE.LASTUSER.001 | DontDisplayLastUserName 缺/0 | =1 静默 |
| 146 | 机器角色工作站/成员/DC | [PLAN W01] | WIN.AD.ROLE.001 | 任意机器 info | 清单默认隐藏 |
| 147 | GPP cpassword | [CTF][A=T1552.006] | WIN.AD.GPP.CPASSWORD.001 | Groups.xml cpassword 非空 | 空属性/无字段不报；不解密 |
| 148 | ntds.dit 副本 | [CTF][A=T1003.003] | WIN.AD.NTDS.COPY.001 | Temp\ntds.dit | 活库 Windows\NTDS\ntds.dit 不报 |
| 149 | ntdsutil IFM | [CTF] | WIN.AD.IFM.001 | Active Directory\ntds.dit | 非 IFM 路径走 COPY |
| 150 | SYSVOL 登录脚本 | [CTF][A=T1037] | WIN.AD.SYSVOL.SCRIPT.001 | SYSVOL\scripts\*.bat | 非 scripts/netlogon 不报 |
| 151 | GPO 立即任务 | [CTF] | WIN.AD.GPO.TASK.001 | ScheduledTasks.xml Exec | 无 Command 不报 |
| 152 | GPO scripts.ini | [CTF] | WIN.AD.GPO.SCRIPTINI.001 | 0CmdLine= | 空 CmdLine 不报 |
| 153 | GPO 委派特权扩大 | [CTF] | WIN.AD.GPO.DELEG.001 | SeEnableDelegationPrivilege 含额外名 | 仅 Administrators SID 不报 |
| 154 | DSRM 在线登录 | [CTF] | WIN.AD.DSRM.LOGON.001 | DsrmAdminLogonBehavior=2 | 缺键/0 不报 |
| 155 | LDAP 不签名 | [技能赛] | WIN.AD.LDAP.NOSIGN.001 | LDAPServerIntegrity=0 | 键不存在不报（工作站） |
| 156 | 域控上 Spooler | [PrintNightmare] | WIN.AD.SPOOLER.DC.001 | looks_like_dc + Start=auto | 工作站无 SYSVOL 不报 |
| 157 | 域控未强制 SMB 签名 | [基线] | WIN.AD.SMBSIGN.001 | looks_like_dc + 未 Require=1 | 非 DC 特征不报 |
| 158 | WDigest 明文 | [CTF] | WIN.BASE.WDIGEST.001 | UseLogonCredential=1 | 缺键不报（避免 Win7 默认误报） |
| 159 | NTLMv1 | [等保] | WIN.BASE.NTLMV1.001 | LmCompatibilityLevel≤2 | ≥3 静默 |
| 160 | PTH LATFP | [CTF] | WIN.BASE.LATFP.001 | =1 | 缺/0 静默 |
| 161 | 存储 LM 哈希 | [等保] | WIN.BASE.NOLMHASH.001 | NoLmHash=0 | 1 静默 |
| 162 | 匿名枚举 SAM | [技能赛] | WIN.BASE.RESTRICTANON.001 | RestrictAnonymousSAM=0 | 1 静默 |
| 163 | Everyone 含匿名 | [技能赛] | WIN.BASE.EVERYONEANON.001 | =1 | 0 静默 |
| 164 | SMB 明文口令 | [技能赛] | WIN.BASE.PLAINSMB.001 | EnablePlainTextPassword=1 | 0/缺 静默 |
| 165 | PointAndPrint 免提权 | [PrintNightmare] | WIN.BASE.PNP.ELEV.001 | NoWarningNoElevationOnInstall=1 | 缺/0 静默 |
| 166 | AlwaysInstallElevated | [CTF] | WIN.BASE.ALWAYSINST.001 | HKLM 或 HKCU=1 | 双 0 静默 |
| 167 | WinRM 明文/Basic | [技能赛] | WIN.BASE.WINRM.UNENC.001 | AllowUnencrypted 或 AllowBasic=1 | 0/缺 静默 |
| 168 | 防火墙配置文件关闭 | [PLAN W12] | WIN.BASE.FW.OFF.001 | EnableFirewall=0 | 全开静默；不自动开启 |
| 169 | GPP 把账户加入本地管理员 | [CTF][A=T1098] | WIN.AD.GPP.ADMIN.001 | Groups.xml groupName=Administrators | 无 Administrators 不报 |
| 170 | GPP Registry.xml 持久化 | [CTF] | WIN.AD.GPP.REG.001 | SYSVOL Registry.xml | 非 sysvol 不报 |
| 171 | LDAP 通道绑定显式关闭 | [技能赛] | WIN.AD.LDAP.BIND.001 | LdapEnforceChannelBinding=0 | 缺键不报（避免全机误报） |
| 172 | 计算机账户密码不再更换 | [基线] | WIN.AD.MACHPWD.001 | DisablePasswordChange=1 | 0 静默 |
| 173 | 安全通道未签名加密 | [技能赛] | WIN.BASE.SEALCHAN.001 | SealSecureChannel=0 或 RequireSignOrSeal=0 | 两键均 1 静默 |
| 174 | LDAP 客户端不签名 | [技能赛] | WIN.BASE.LDAPCLIENT.001 | LDAPClientIntegrity=0 | 缺/≥1 静默 |
| 175 | UAC 管理员不提示 | [技能赛] | WIN.BASE.UAC.NOPROMPT.001 | ConsentPromptBehaviorAdmin=0 | 5 静默 |
| 176 | 关闭 Ctrl+Alt+Del 登录注意 | [技能赛] | WIN.BASE.DISABLECAD.001 | DisableCAD=1 | 0/缺 静默 |
| 177 | 非管理员可装打印驱动 | [PrintNightmare] | WIN.BASE.PNP.ADMIN.001 | RestrictDriverInstallationToAdministrators=0 | 1/缺 静默 |
| 178 | RDP 安全层为 RDP | [技能赛] | WIN.BASE.RDP.SECLAYER.001 | SecurityLayer=0 | 1/2 静默 |
| 179 | 缓存域登录数过大 | [基线] | WIN.BASE.CACHEDLOGON.001 | CachedLogonsCount≥50 | ≤10 静默 |
| 180 | 超过登录时间不强制注销 | [技能赛] | WIN.BASE.FORCELOGOFF.001 | enableforcedlogoff=0 | 1 静默 |
| 181 | NTLM 会话安全为 0 | [等保] | WIN.BASE.NTLMSEC.001 | NtlmMinClientSec=0 | 0x20080000 静默 |
| 182 | PowerShell Unrestricted/Bypass | [CTF] | WIN.BASE.PS.UNRESTRICT.001 | 计算机策略 Unrestricted | Restricted 静默 |
| 183 | SAM/SYSTEM/SECURITY 注册表副本 | [CTF][A=T1003.002] | WIN.AD.HIVE.COPY.001 | Temp\sam.save / IFM registry\SYSTEM | system32\config 活库不报 |
| 184 | lsass 内存转储 | [CTF][A=T1003.001] | WIN.AD.LSASS.DMP.001 | Temp\lsass.dmp | lsass.exe 不报 |
| 185 | GPP Files/Shortcuts.xml | [CTF] | WIN.AD.GPP.FILE.001 | SYSVOL Files.xml | 非 sysvol 不报 |
| 186 | GPP Services.xml | [CTF] | WIN.AD.GPP.SVC.001 | SYSVOL Services.xml | 非 sysvol 不报 |
| 187 | RDP 加密级别过低 | [技能赛] | WIN.BASE.RDP.ENCRYPT.001 | MinEncryptionLevel≤1 | 缺键/≥2 静默 |
| 188 | Remote Registry 自动启动 | [技能赛] | WIN.BASE.REMOTEREG.001 | Start=AUTO | 手动/禁用静默 |
| 189 | 网络访问按来宾模型 | [技能赛] | WIN.BASE.FORCEGUEST.001 | ForceGuest=1 | 0/缺 静默 |

合计 **189** 检测点（142 + v0.8 AD/Server 47）。新检测点必须：先入本表 → 实现 → 单测/夹具 → 断言通过。
域账户 LDAP、krbtgt、DCSync、黄金票、ADCS 仍不在本表（见 AD-SERVER-POINTS.md D 节，C 级）。
