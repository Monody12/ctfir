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
| 启动项/注册表 | WIN.AUTORUN.*（Run/Winlogon/IFEO/AppInit/LSA/登录脚本/BootExecute） | startup | 主路径+参数路径都提取 |
| 粘滞键后门 | WIN.HASHES（sethc/utilman…） | hash | 与可信同版本比对；IFEO 分支另查 |
| SSH 后门 | LNX.SSH.*（AUTHKEY/PRIVKEY/CONFIG） | sshkey | 指纹逐条核对；forced command 高危 |
| preload/库劫持 | LNX.PERSIST.PRELOAD / LNX.LDSO.INJECT | preload | 配置行+库哈希；不加载不删除先取证 |
| webshell | WIN.WEB.WEBSHELL / LNX.WEB.SHELL | webshell | 静态特征命中≠定罪；隔离先于删除 |
| 攻击者 IP | WIN.WEB.LOGPOST / LNX.WEB.LOGPOST / WIN.EVT.AUTHFAIL / LNX.LOG.AUTHFAIL | log | POST Top IP + 4625/failed Top IP |
| 攻击者执行了什么 | Prefetch/ShimCache/bash_history/wtmp/lastlog | log | 文件名即程序名；历史是线索非结论 |
| U 盘取证 | WIN.USB（USBSTOR） | log | 配合 setupapi.dev.log 看时间 |
| 哈希比对/文件篡改 | --baseline + WIN.FILES.BASELINE / LNX.FILES.BASELINE | hash | 自带基线清单文件即可判定 |
| 服务后门 | WIN.SVC.SUSPECT / WIN.DRV.WRITABLE | service | 可写路径+未引号+签名三看 |
| 提权痕迹 | LNX.SUID.UNEXPECTED / LNX.CAPS | user | 白名单外即人工核实 |
| 弱口令爆破 | 4625 Top IP / secure Failed | log | 时间窗内集中失败 |
| 处置后复查 | ctfir diff --a 处置前 --b 处置后 | — | resolved=已清除 added=新出现 |

**三不变**：工具只读；PASS≠安全；未完成检查如实列出。
