# DETECTION-POINTS — 检测点全表 v0.3（用例需求的唯一来源）

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

合计 100 检测点 ↔ 用例库目标 100+ 行。新检测点必须：先入本表（含正负例设计）→ 实现 → 用例行 → 断言通过。
