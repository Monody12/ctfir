#include "advice.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace ctfir {

// 每条建议：现场能照着做的短句。命令在「一条命令」里，这里只补注意点。
static const Advice kAdvices[] = {
{"ADVICE.ACC.REVIEW.001", "可疑账户",
 "先看它还挂了什么：计划任务、启动项、SSH 钥匙、crontab。\n"
 "Windows：net user <账户名> 看组。安全日志 4720 是谁建的。先 /active:no，确认没人用再 /delete。\n"
 "Linux：id <用户名>。名字不是 root 但 UID=0，就是第二个 root，先 usermod -L。\n"
 "家目录是 /tmp 时不要 userdel -r。sudoers.d 里的免密文件直接 rm。"},

{"ADVICE.LOGIN_HIDE.REVIEW.001", "登录界面把账户藏起来了",
 "值=0 就是欢迎界面不显示这个账户。先 net user 确认人还在。\n"
 "只删这一条值，别把整个 UserList 键删掉。账户本身按可疑账户处理。"},

{"ADVICE.TASK.REVIEW.001", "计划任务",
 "schtasks /query /tn \"<任务路径>\" /xml 存一份，看 Action 指向哪个文件。\n"
 "\\Microsoft\\ 下面大多是系统自带。指向 Temp、带 certutil、powershell -enc 的优先删。\n"
 "先 /end 再 /delete。被调用的脚本先拷走。"},

{"ADVICE.SVC.REVIEW.001", "可疑服务",
 "sc qc \"<服务名>\" 看 ImagePath。落在 Temp、用户目录、路径有空格却没加引号，都要处理。\n"
 "先 start= disabled，再 stop，确认不是业务再 sc delete。二进制先拷走。"},

{"ADVICE.AUTORUN.REVIEW.001", "启动项 / 映像劫持",
 "reg query 把完整值读出来。IFEO 的 Debugger 不是调试器，就是粘滞键一类后门。\n"
 "AppInit_DLLs 清空两个视图（64 位和 Wow6432Node），对应 .dll 再 del。\n"
 "Startup 里的 .vbs/.bat/.exe 直接 del。改完注销一次看还会不会起来。"},

{"ADVICE.HOSTS.REVIEW.001", "hosts 被改了",
 "只删恶意那一行，不要清空文件。\n"
 "Linux：Ubuntu 的 127.0.1.1 本机名是安装器写的，一般不用动。\n"
 "Windows：改完执行 ipconfig /flushdns。"},

{"ADVICE.SSHKEY.REVIEW.001", "SSH 密钥 / 配置",
 "authorized_keys 一行一把钥匙。多出来的、带 command= 的先拿掉。authorized_keys2 也要看。\n"
 "备份后删那一行，权限保持 600。点开头的密钥文件直接移走。\n"
 "PermitRootLogin yes 按题面改回 no，改完 sshd -t 再 reload。"},

{"ADVICE.CRON.REVIEW.001", "cron / at / timer / init",
 "被引用的脚本要打开看全文。带 curl|sh、/tmp、/dev/tcp 的整行删掉。\n"
 "cron.d 下一份独立文件可以直接 rm。systemd：disable --now，把 unit 移走，再 daemon-reload。\n"
 "SysV：删 /etc/init.d 下那份脚本。at 队列把 spool 文件删掉。"},

{"ADVICE.PROFILE.REVIEW.001", "bashrc / profile / 历史",
 "看 alias、函数、PROMPT_COMMAND、PATH 前面是不是被塞了 /tmp。可疑行删掉。\n"
 "history 只当线索：curl 官网没意义；curl|sh、/dev/tcp、写 authorized_keys 才顺着追。\n"
 "新开一个 shell，确认 ls、ssh、su 还是原来的命令。"},

{"ADVICE.PRELOAD.REVIEW.001", "动态库 / PAM 劫持",
 "cat /etc/ld.so.preload，有内容就清空，对应 .so 先拷走再删。\n"
 "ld.so.conf.d 里 /usr/lib、/lib、/usr/local/lib 是发行版默认；指向 /tmp 或 /home 的才删。\n"
 "PAM：只删 pam_exec、临时目录 .so 那一行，别整份 pam.d 清空，否则可能登不进去。"},

{"ADVICE.WEBSHELL.REVIEW.001", "webshell / 站点文件",
 "打开文件看 eval、assert、$_POST。先改名移出站点目录，同目录其他 php/jsp/aspx 再扫一遍。\n"
 "access 日志搜这个文件名，把攻击 IP 写进报告。入口不修，马还会回来。"},

{"ADVICE.MINER.REVIEW.001", "挖矿 / 伪装进程",
 "记下 PID、命令行、exe 路径。名字叫 kworkerd 却指向 sleep，按后门处理。\n"
 "Windows：taskkill /PID <pid> /F\n"
 "Linux：kill -STOP <pid>，确认后 kill。\n"
 "只杀进程不够，cron、服务、启动项里拉起它的那条要一起删。"},

{"ADVICE.HASH.BASELINE.001", "文件和系统命令",
 "先看路径：系统目录被换过才是替换攻击。\n"
 "Windows：先 copy 一份，再 del。桌面和 Temp 里刚出现的 exe 优先处理。\n"
 "Linux：ls、ps、netstat 变得很小，多半被换成脚本。rpm -V / dpkg -V 对一下，先拷走再重装包。"},

{"ADVICE.FILE.REVIEW.001", "近期出现的文件",
 "这是线索，对照题面给的时间窗口，不是每条都要删。\n"
 "Windows：自己的扫描器和 VMware 升级包不用管。陌生 exe 先 copy 再 del。\n"
 "Linux：/tmp、家目录下刚出现的脚本先移走。/etc 里被改过的对照启动项。"},

{"ADVICE.HARDEN.001", "基线没达到",
 "这类不是后门，是密码策略、TMOUT、防火墙这类开关。先清后门，题面要求加固再改。\n"
 "root 的 shell 是 /bin/bash 是正常的，不要改成 nologin。改防火墙前先放行自己的 SSH/RDP。"},

{"ADVICE.AD.REVIEW.001", "GPP / NTDS / SYSVOL",
 "Groups.xml 里有 cpassword 就删这个 XML，被写进去的本地管理员口令要换。明文不要写进交卷。\n"
 "Temp、桌面上的 ntds.dit、sam.save、lsass.dmp 先拷走再删。\n"
 "ProductType 不是 LanmanNT 就不要关 Print Spooler。工作站这条只是对照，不用改。"},

{"ADVICE.EVENTLOG.REVIEW.001", "日志 / 命令历史",
 "失败次数多，把 Top IP 写进报告。4720/4732 看是谁建的账户。1102 表示安全日志被清过。\n"
 "PowerShell 历史里的 IEX、-enc、DownloadString 顺着 IP/URL 追。\n"
 "不要 wevtutil cl，也不要清空 history。"},

{"ADVICE.TOOLS.REVIEW.001", "攻击工具 / 伪装文件",
 "fscan、frp、nps、chisel 这类直接删。frpc.ini 里的 server_addr 写进报告。\n"
 "invoice.pdf.exe 这种双扩展名先拷走再 del。别当普通文档打开。\n"
 "/tmp/.sshlog、.pam_pass 这类口令记录直接 rm，不要把密码抄进报告。"},

{"ADVICE.RANSOM.REVIEW.001", "勒索信 / 加密后缀",
 "先把勒索信拷走当证据，再删桌面上的 README/DECRYPT。\n"
 "加密后缀文件不要解密，交卷写发现时间和范围即可。"},

{"ADVICE.RMT.REVIEW.001", "远控软件",
 "向日葵、ToDesk、TeamViewer、AnyDesk：题面要求卸载就卸。\n"
 "向日葵日志在 SunloginClient\\log，搜 PowerShell 路径遍历痕迹。目录可 rd /s /q。"},

{"ADVICE.MID.REVIEW.001", "Redis / MySQL",
 "Redis 无密码或 bind 0.0.0.0：改 bind 127.0.0.1，加上 requirepass，再查 crontab 和 authorized_keys 有没有被写。\n"
 "MySQL UDF、general_log 里的 shell、慢查询里的 INTO OUTFILE，把文件移走。日志本身不要删。"},
};

const Advice* find_advice(const std::string& advice_id) {
    for (const auto& a : kAdvices)
        if (advice_id == a.id) return &a;
    return nullptr;
}

} // namespace ctfir
