#include "advice.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace ctfir {

// 六步制（核实→留证→停用→清除→验证→复盘）。全部文本；<占位符> 由用户核实替换；
// 严禁跳过"停用"直接删除；凡不可逆操作前必须完成留证。工具不执行任何命令。
static const Advice kAdvices[] = {
{"ADVICE.ACC.REVIEW.001", "可疑账户处置手册",
 "【1-核实】Windows: `net user <账户名>` 看活动/组/描述；`wmic useraccount where \"Name='<账户名>'\" get SID,Disabled`；"
 "对照创建事件(4720)时间与运维记录。Linux: `id <用户名>`；`getent passwd <用户名>`；UID0 非 root 优先核查。\n"
 "【2-留证】导出全部属性与归属：Windows 截图 + `net user <账户名>` 输出；Linux `grep <用户名> /etc/passwd` 输出、"
 "该用户 crontab（`crontab -u <用户名> -l`）、authorized_keys、进程（`ps -u <用户名>`）、文件（`find / -user <用户名> 2>/dev/null`）。\n"
 "【3-停用】确认可疑后先停用不删除：Windows `net user <账户名> /active:no`；"
 "Linux `usermod -L <用户名>` 并 `usermod -s /usr/sbin/nologin <用户名>`。\n"
 "【4-清除】观察无业务影响后：Windows `net user <账户名> /delete`；"
 "Linux 先清理其名下任务/密钥再 `userdel -r <用户名>`（家目录有业务文件时改为手动归档）。\n"
 "【5-验证】重跑 ctfir 扫描该账户消失；尝试以该账户登录应失败；复查其任务/密钥/进程无残留。\n"
 "【6-复盘】排查创建途径：Windows 事件 4720/4732 的操作者；Linux authorized_keys 变更、"
 "web 入口、sudo 审计——堵住入口才算处置完成。"},

{"ADVICE.LOGIN_HIDE.REVIEW.001", "登录界面隐藏账户处置手册",
 "【1-核实】`reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\"`；"
 "确认同名账户是否存在（net user）及状态；服务账户隐藏属常见。\n"
 "【2-留证】记录值名/类型/数据原值（本工具证据已含）；关联 4720 创建时间。\n"
 "【3-停用】如账户存在且可疑：`net user <账户名> /active:no`。\n"
 "【4-清除】仅删除该同名值（恢复登录界面显示）："
 "`reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v <账户名> /f`；"
 "随后按账户处置手册处理账户本体。不要删除整个 UserList 键。\n"
 "【5-验证】注销/重启后核对登录界面与 `net user` 一致。\n"
 "【6-复盘】检查该账户如何被创建与隐藏（脚本/远控/手动）。"},

{"ADVICE.TASK.REVIEW.001", "计划任务处置手册",
 "【1-核实】导出 XML：`schtasks /query /tn \"<任务路径>\" /xml` /XML；读 Action 指向与参数；"
 "确认任务路径（\\Microsoft\\ 开头为系统自带，自定义路径重点看）。\n"
 "【2-留证】保存 XML 与被引用脚本文件副本（只读复制）+ 脚本哈希。\n"
 "【3-停用】`schtasks /change /tn \"<任务路径>\" /disable`（先停用观察业务影响）。\n"
 "【4-清除】确认后删除任务：`schtasks /delete /tn \"<任务路径>\" /f`；"
 "被引用脚本/程序取证后隔离（改名或移出，不要在取证前删除）。\n"
 "【5-验证】重扫任务消失；观察其网络连接/进程不再出现。\n"
 "【6-复盘】任务由谁创建（XML Author 字段）+ 被引用脚本来源；修复入侵入口。"},

{"ADVICE.SVC.REVIEW.001", "服务处置手册",
 "【1-核实】`sc qc \"<服务名>\"` + `sc query \"<服务名>\"`；核对 ImagePath 真实性与签名、启动类型、运行账号。\n"
 "【2-留证】记录 Start/ImagePath/Type/Account 原值；二进制文件哈希。\n"
 "【3-停用】`sc config \"<服务名>\" start= disabled` 后重启验证（不停用直接删会留孤儿配置）。\n"
 "【4-清除】确认无业务影响后 `sc delete \"<服务名>\"`；二进制取证后隔离。\n"
 "【5-验证】重启后服务不存在；其进程/网络连接消失。\n"
 "【6-复盘】服务注册时间与来源（安装包/脚本/远控）；同路径兄弟文件排查。"},

{"ADVICE.AUTORUN.REVIEW.001", "自启动项处置手册",
 "【1-核实】`reg query \"<精确键路径>\"` 读完整值；核对引用文件存在性/签名/创建时间；IFEO Debugger 指向非调试器属高危。\n"
 "【2-留证】`reg export \"<键>\" <文件>.reg` 保存原值；引用文件哈希。\n"
 "【3-停用】把值数据改名加后缀（如 .bak）或暂时移除值（先 export 有了备份）。\n"
 "【4-清除】确认后删除该值：`reg delete \"<精确键路径>\" /v <值名> /f`；引用文件取证后隔离。\n"
 "【5-验证】重启后项不再加载；进程/网络无复现。\n"
 "【6-复盘】值由谁写入（安装器/脚本/手工）；Startup 文件夹与 Run 键全量复查。"},

{"ADVICE.HOSTS.REVIEW.001", "hosts 映射处置手册",
 "【1-核实】逐行确认每条映射用途：内网服务/IP 是否符合拓扑/注释来源；回环绑定陌生域名重点看。\n"
 "【2-留证】完整复制 hosts 原文件与哈希（工具已留证）。\n"
 "【3-停用】注释对应行（行首加 #）即可立即失效——优先注释而非删除。\n"
 "【4-清除】确认后删除对应行；不要清空整个文件。\n"
 "【5-验证】Windows `ipconfig /flushdns` 后验证解析恢复。\n"
 "【6-复盘】行是何时/被什么写入（安装器/恶意脚本）；关注常见劫持域（银行/杀软更新/比赛平台）。"},

{"ADVICE.SSHKEY.REVIEW.001", "authorized_keys / SSH 配置处置手册",
 "【1-核实】逐条公钥与本人/运维清单比对（指纹）；关注 forced command、无来源限制、近期添加；"
 "私钥文件出现在异常用户目录需溯源。\n"
 "【2-留证】备份 authorized_keys 原文件与权限（0600/属主）+ 每条指纹（工具已输出，不保存私钥内容）。\n"
 "【3-停用】临时禁用对应行（行首加 options 前缀 `no-auth-fallback,`？——正确做法：注释掉该行或 "
 "暂时 `sshd_config` 设 `PubkeyAuthentication no` 后 `systemctl reload sshd`）。\n"
 "【4-清除】确认后删除对应行（保持权限 0600）；可疑私钥文件移出归档。\n"
 "【5-验证】用该 key 尝试登录应失败；核对 secure/auth.log 中该 key 使用记录消失。\n"
 "【6-复盘】key 何时/如何进入（webshell 写入/弱口令后植入）；同用户 cron/profile 联查。"},

{"ADVICE.CRON.REVIEW.001", "cron/at/systemd timer 处置手册",
 "【1-核实】读被引用脚本全文（不要只看任务行）；核对脚本属主/可写目录/网络行为。\n"
 "【2-留证】备份 crontab/任务文件与被引用脚本（含权限属主）+ 哈希。\n"
 "【3-停用】注释对应行（行首 #）或 `systemctl disable --now <timer>`（先停用）。\n"
 "【4-清除】确认后删除行/任务文件；脚本取证后隔离；at 队列 `atrm <编号>`。\n"
 "【5-验证】等待触发周期确认不再执行；/var/log/cron 停止记录。\n"
 "【6-复盘】任务写入途径（root 弱口令/redis 未授权/webshell）；检查是否被周期性重建（守护进程互拉）。"},

{"ADVICE.PROFILE.REVIEW.001", "shell 配置处置手册",
 "【1-核实】逐行读配置（不执行）；PROMPT_COMMAND/alias/PATH 前置目录重点关注。\n"
 "【2-留证】备份原文件（权限/属主）+ 行号。\n"
 "【3-停用】注释可疑行（行首 #）。\n"
 "【4-清除】确认后删除行；同用户 crontab/authorized_keys 联查。\n"
 "【5-验证】新开 shell 验证行为正常。\n"
 "【6-复盘】写入途径与时间（文件 mtime）；多用户批量排查。"},

{"ADVICE.PRELOAD.REVIEW.001", "preload 处置手册",
 "【1-核实】读 /etc/ld.so.preload 配置行；核对库文件属主/时间/是否被包管理器收录；不加载不删除先取证。\n"
 "【2-留证】配置原值 + 库文件哈希与副本。\n"
 "【3-停用】注释配置行（立即生效于新进程）。\n"
 "【4-清除】确认后删除行；库文件取证后隔离。\n"
 "【5-验证】重启后进程行为/网络恢复正常。\n"
 "【6-复盘】库的投递途径；同目录其他可疑库排查。"},

{"ADVICE.WEBSHELL.REVIEW.001", "疑似 webshell 处置手册",
 "【1-核实】读文件全文（参数来源/执行函数/认证逻辑）；确认所属框架是否误报；"
 "在 access 日志检索该路径定位攻击 IP 与时间。\n"
 "【2-留证】副本+哈希+mtime+属主+相关日志——四件套齐备前不动原文件。\n"
 "【3-停用】先隔离：改名（shell.php → shell.php.quarantine）或移出 web 根到归档目录（保留现场）。\n"
 "【4-清除】取证完成后删除；同时修复入口（上传漏洞/弱口令/未授权接口）。\n"
 "【5-验证】重扫 web 根；该路径日志访问停止；同目录同类文件复查。\n"
 "【6-复盘】攻击时间线：上传 IP → 落地 → 后续动作；检查其他站点/目录是否同样沦陷。"},

{"ADVICE.MINER.REVIEW.001", "疑似挖矿进程处置手册",
 "【1-核实】记录 PID/命令行/exe 路径/哈希/连接目标（工具证据已含）；确认是否业务自身程序。\n"
 "【2-留证】样本文件复制 + 命令行截图 + 网络连接记录。\n"
 "【3-停用】Windows `taskkill /PID <pid> /F`；Linux 先 `kill -STOP <pid>`（暂停观察）再 `kill <pid>`。\n"
 "【4-清除】清除其持久化入口（按任务/服务/启动项/cron 手册处理）；样本取证后删除。\n"
 "【5-验证】CPU 恢复；连接消失；观察是否被守护进程拉起（互拉要一起处理）。\n"
 "【6-复盘】入侵路径（弱口令/未授权服务/漏洞）；修复入口后持续观察复发。"},

{"ADVICE.HASH.BASELINE.001", "哈希基线不一致处置手册",
 "【1-核实】与可信来源比对：同版本系统/软件包官方哈希、`rpm -V <包>`、干净同版本机器；"
 "区分合理变化（配置/补丁/换行转换）与篡改。\n"
 "【2-留证】当前哈希清单（integrity.sha256）+ 可信来源哈希截图。\n"
 "【3-停用】若判定被篡改：隔离文件（改名），系统二进制考虑从可信介质恢复。\n"
 "【4-清除】恢复原版文件（可信源）；修复被利用的写入途径。\n"
 "【5-验证】重扫哈希与基线对齐。\n"
 "【6-复盘】写入时间与途径；关联账户/任务/进程事件还原时间线。"},

{"ADVICE.HARDEN.001", "Windows/Linux 基线加固手册",
 "【1-核实】对照赛题/等保要求读当前值（net accounts、reg query、auditpol、sshd_config）。非默认不必等于恶意。\n"
 "【2-留证】导出原值（reg query / secedit / net accounts）写入报告。\n"
 "【3-停用】先改可逆项（注册表 DWORD、net accounts）；观察业务/远程管理是否仍可用。\n"
 "【4-清除】按报告已填命令把策略收到基线；域环境应改 GPO 而不是只改本机。\n"
 "【5-验证】重跑 ctfir，对应 WIN.BASE / LNX.BASE 项消失或降级。\n"
 "【6-复盘】域控上的 LDAP/SMB 签名、Spooler、NTLMv1 影响全域；改完 gpupdate /force 并抽查成员机。"},

{"ADVICE.AD.REVIEW.001", "域控 / SYSVOL / NTDS 处置手册",
 "【1-核实】确认本机角色：ProductType LanmanNT=DC，ServerNT=成员服务器，WinNT=工作站。"
 "本地 SAM 不是 Domain Admins。GPP XML 的 cpassword 用 gpp-decrypt 可解，但不要把明文写进提交物。\n"
 "【2-留证】复制 SYSVOL 异常 XML/脚本、ntds.dit 副本、IFM 目录、SAM/SYSTEM.save、lsass.dmp 到证据区；记录路径与哈希。不要用 mimikatz/secretsdump 把哈希打进报告。\n"
 "【3-停用】域控上无打印则停 Spooler；DSRM 登录行为改回 0；LDAPServerIntegrity=2。\n"
 "【4-清除】删除 GPP 含 cpassword 的 XML、Files/Services/Registry.xml、GPO 立即任务、SYSVOL 恶意脚本、ntds.dit 副本、IFM、sam.save 与 lsass.dmp；"
 "轮换被 GPP 写入的本地管理员口令；若确认 NTDS 被拷走，按应急预案两次重置 krbtgt。\n"
 "【5-验证】重扫 WIN.AD.* 文件项消失；\\\\<domain>\\SYSVOL 不再有 cpassword；ntdsutil 临时目录清空。\n"
 "【6-复盘】DCSync/委派/ADCS/黄金票据需要 LDAP 与事件 4662/4769，本工具不覆盖——用 AD 工具与安全日志人工查。"},

{"ADVICE.EVENTLOG.REVIEW.001", "登录/账户事件处置手册",
 "【1-核实】Top 失败 IP 是否内网授权资产；4624 登录类型（2=控制台 3=网络 10=RDP）与账户是否合理；"
 "4720/4732 操作者是谁。\n"
 "【2-留证】导出相关时间窗事件（工具已留证）。\n"
 "【3-停用】确认爆破/后门账户后按账户手册停用。\n"
 "【4-清除】网络侧阻断/加固不在本工具职责（给出建议文本：防火墙限制来源、改密、关闭暴露面）。\n"
 "【5-验证】失败量趋势回落。\n"
 "【6-复盘】成功登录与失败来源重叠时间段的全部动作复盘。"},
};

const Advice* find_advice(const std::string& advice_id) {
    for (const auto& a : kAdvices)
        if (advice_id == a.id) return &a;
    return nullptr;
}

} // namespace ctfir
