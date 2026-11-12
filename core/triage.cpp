#include "triage.hpp"
#include "util.hpp"

#include <algorithm>

namespace ctfir {

const char* bucket_id(Bucket b) {
    switch (b) {
    case Bucket::Clear: return "clear";
    case Bucket::Harden: return "harden";
    case Bucket::Trace: return "trace";
    case Bucket::Web: return "web";
    case Bucket::Inventory: return "inventory";
    }
    return "trace";
}

const char* bucket_zh(Bucket b) {
    switch (b) {
    case Bucket::Clear: return "立刻清";
    case Bucket::Harden: return "再加固";
    case Bucket::Trace: return "溯源";
    case Bucket::Web: return "Web/中间件";
    case Bucket::Inventory: return "清单/事实";
    }
    return "溯源";
}

int bucket_rank(Bucket b) { return static_cast<int>(b); }

int severity_rank(const std::string& sev) {
    if (sev == "high") return 0;
    if (sev == "medium") return 1;
    if (sev == "low") return 2;
    if (sev == "info") return 3;
    return 4;
}

int confidence_rank(const std::string& conf) {
    if (conf == "high") return 0;
    if (conf == "medium") return 1;
    if (conf == "low") return 2;
    return 3;
}

static bool has(const std::string& rid, const char* needle) {
    return rid.find(needle) != std::string::npos;
}

Bucket bucket_of(const std::string& rule_id) {
    const std::string& r = rule_id;
    if (has(r, "INVENTORY") || has(r, "TASK.FACT") || has(r, "TIMER.FACT") ||
        has(r, "FILES.RECENT") || has(r, "BASE.RECENT") || has(r, "FILES.TEMPEXE") ||
        has(r, "CMDRECENT"))
        return Bucket::Inventory;

    if (has(r, "WEB.LOGPOST") || has(r, "WEB.LOGATTACK") || has(r, ".EVT.") ||
        has(r, ".LOG.") || has(r, "TRACE.") || has(r, "PSHIST") ||
        has(r, "AUTHFAIL") || has(r, "PREFETCH") || has(r, "LOGCLEAR") ||
        has(r, "BTMP"))
        return Bucket::Trace;

    if (has(r, "MYSQL") || has(r, "REDIS") || has(r, "PHP.") ||
        has(r, "WEB.CREDS") || has(r, "WEB.GITLEAK") || has(r, "DROPRIGHT") ||
        has(r, "WEB.BACKUP"))
        return Bucket::Web;

    if (has(r, "COMHIJACK") || has(r, "WMICONSUMER") || has(r, "SVCDLL") ||
        has(r, "ACTIVESETUP") || has(r, "CORPROFILER") || has(r, "SCRNSAVE") ||
        has(r, "AUTOLOGON") || has(r, "NETSH") || has(r, "PSPROFILE") ||
        has(r, "LNKTARGET"))
        return Bucket::Clear;

    if (has(r, ".BASE.") || has(r, "AUDIT.") || has(r, "SHADOWPERM") ||
        has(r, "FW.WRITABLE") || has(r, "SSH.CONFIG") || has(r, "SSH.PWDAUTH") ||
        has(r, "SSH.MAXAUTH") || has(r, "SSH.PORT"))
        return Bucket::Harden;

    if (has(r, "AUTORUN") || has(r, "PERSIST") || has(r, "TASK.SUSPECT") ||
        has(r, "TASK.REFPATH") || has(r, "SVC.") || has(r, "HOSTS") ||
        has(r, "PORTPROXY") || has(r, "SHARE.NONDEFAULT") || has(r, "DOUBLEEXT") ||
        has(r, "FILES.ADS") || has(r, "WEBSHELL") || has(r, "WEB.SHELL") ||
        has(r, "BLACKLINK") || has(r, "CONFIGBACKDOOR") || has(r, "SSH.AUTHKEY") ||
        has(r, "SSH.PRIVKEY") || has(r, "SSH.HIDDENKEY") || has(r, "SSH.PROXYCMD") ||
        has(r, "SSHLOG") || has(r, "TOOLS") || has(r, "RANSOM") || has(r, "RMT.") ||
        has(r, "PROC.") || has(r, "DRV.WRITABLE") || has(r, "SUID") ||
        has(r, "CAPS.") || has(r, "LDSO") || has(r, ".ACC."))
        return Bucket::Clear;

    return Bucket::Trace;
}

bool is_known_ms_activesetup(const std::string& object_ref) {
    // Win7/IE/WMP 预装 CLSID，赛场常见误报；检测仍写入 findings，默认进清单
    static const char* kGuid[] = {
        "22d6f312-b0f6-11d0-94ab-0080c74c7e95",
        "2c7339cf-2b09-4501-b3f3-f3508c9228ed",
        "44bba840-cc51-11cf-aafa-00aa00b6015c",
        "6bf52a52-394a-11d3-b153-00c04f79faa6",
        "89820200-ecbd-11cf-8b85-00aa005b4340",
        "89820200-ecbd-11cf-8b85-00aa005b4383",
        "08b0e5c0-4fcb-11cf-aaa5-00401c608501",
        "64d2d77b-f306-4710-b5d2-adf28c3b85f8",
        nullptr
    };
    std::string l = to_lower(object_ref);
    for (int i = 0; kGuid[i]; ++i)
        if (l.find(kGuid[i]) != std::string::npos) return true;
    return false;
}

Bucket bucket_of(const Finding& f) {
    Bucket b = bucket_of(f.rule_id);
    if (has(f.rule_id, "ACTIVESETUP") && is_known_ms_activesetup(f.object_ref))
        return Bucket::Inventory;
    return b;
}

static const struct TitleRow { const char* id; const char* title; } kTitles[] = {
    {"WIN.ACC.DOLLAR.001", "美元号后门账户"},
    {"WIN.ACC.INVENTORY.001", "本地账户全量清单"},
    {"WIN.ACC.CUSTOM.001", "自建本地账户"},
    {"WIN.ACC.ADMIN.001", "自建账户在管理员组"},
    {"WIN.ACC.GUESTADMIN.001", "Guest 被加入管理员组"},
    {"WIN.ACC.LOGIN_HIDE.001", "登录界面隐藏账户"},
    {"WIN.SVC.SUSPECT.001", "可疑服务（可写路径）"},
    {"WIN.SVC.UNQUOTED.001", "服务路径未加引号"},
    {"WIN.AUTORUN.SUSPECT.001", "启动项含解释器/下载特征"},
    {"WIN.AUTORUN.WRITABLE.001", "启动项指向可写目录"},
    {"WIN.AUTORUN.REFPATH.001", "启动项引用非常规路径"},
    {"WIN.AUTORUN.LOGONSCRIPT.001", "Winlogon 登录脚本"},
    {"WIN.AUTORUN.BOOTEXECUTE.001", "BootExecute 非默认"},
    {"WIN.AUTORUN.WINLOGON.001", "Winlogon Shell/Userinit 异常"},
    {"WIN.AUTORUN.APPINIT.001", "AppInit_DLLs 非空"},
    {"WIN.AUTORUN.IFEO.001", "映像劫持（IFEO Debugger）"},
    {"WIN.AUTORUN.LSA.001", "LSA 包注入"},
    {"WIN.HOSTS.LOOPBACK.001", "hosts 回环绑陌生名"},
    {"WIN.HOSTS.MAP.001", "hosts 非默认映射"},
    {"WIN.TASK.FACT.001", "计划任务事实项"},
    {"WIN.TASK.SUSPECT.001", "可疑计划任务"},
    {"WIN.TASK.REFPATH.001", "任务引用非常规路径"},
    {"WIN.PROC.MINER.001", "疑似挖矿进程"},
    {"WIN.EVT.SVC7045.001", "服务安装事件 7045/4697"},
    {"WIN.EVT.ACC.CREATE.001", "账户创建事件 4720"},
    {"WIN.EVT.ACC.TIMELINE.001", "账户变更时间线"},
    {"WIN.EVT.LOGCLEAR.001", "事件日志被清空"},
    {"WIN.EVT.AUTHFAIL.001", "登录失败爆破 Top IP"},
    {"WIN.WEB.WEBSHELL.001", "疑似 webshell"},
    {"WIN.WEB.BLACKLINK.001", "网页黑链/黑页"},
    {"WIN.TOOLS.ARTIFACT.001", "攻击工具残留"},
    {"WIN.TOOLS.FRPCFG.001", "frp/nps 配置残留"},
    {"WIN.WEB.LOGPOST.001", "Web 日志 POST Top IP"},
    {"WIN.WEB.LOGATTACK.001", "Web 日志攻击特征"},
    {"WIN.PROC.CMDLINE.001", "进程命令行可疑"},
    {"WIN.FILES.DOUBLEEXT.001", "双扩展名伪装文件"},
    {"WIN.FILES.TEMPEXE.001", "临时目录可执行文件"},
    {"WIN.FILES.RECENT.001", "近期新增可执行文件"},
    {"WIN.FILES.BASELINE.001", "基线文件内容不一致"},
    {"WIN.FILES.BASELINE.MISS.001", "基线文件缺失"},
    {"WIN.RANSOM.TRACE.001", "勒索痕迹"},
    {"WIN.RANSOM.WALLPAPER.001", "桌面壁纸被篡改"},
    {"WIN.TRACE.PSHIST.001", "PowerShell 历史可疑命令"},
    {"WIN.FILES.ADS.001", "NTFS 隐藏数据流"},
    {"WIN.AUDIT.DISABLED.001", "审核策略子类关闭"},
    {"WIN.BASE.PWDLEN.001", "密码最小长度过短"},
    {"WIN.BASE.LOCKOUT.001", "账户锁定阈值未设"},
    {"WIN.BASE.NOPASSWD.001", "账户空口令"},
    {"WIN.BASE.GUEST.001", "Guest 账户已启用"},
    {"WIN.BASE.RDP.NONLA.001", "RDP 未限制 NLA"},
    {"WIN.BASE.SMB1.001", "SMBv1 仍启用"},
    {"WIN.BASE.AUTOLOGON.001", "自动登录写入明文口令"},
    {"WIN.BASE.LOGRET.001", "事件日志保留过短"},
    {"WIN.BASE.DBEXPOSE.001", "数据库端口对外暴露"},
    {"WIN.BASE.UNUSUALPORT.001", "非常规监听端口"},
    {"WIN.BASE.WMICONSUMER.001", "WMI 事件订阅持久化"},
    {"WIN.BASE.COMHIJACK.001", "COM 劫持"},
    {"WIN.BASE.SCRNSAVE.001", "屏幕保护程序劫持"},
    {"WIN.BASE.SVCDLL.001", "服务 DLL 劫持"},
    {"WIN.PORTPROXY.001", "netsh portproxy 端口转发"},
    {"WIN.BASE.NETSH.001", "Netsh Helper DLL"},
    {"WIN.BASE.ACTIVESETUP.001", "Active Setup 持久化"},
    {"WIN.BASE.CORPROFILER.001", "COR Profiler 注入"},
    {"WIN.BASE.DEFEXCL.001", " Defender 排除项"},
    {"WIN.BASE.PORTMON.001", "异常端口监视"},
    {"WIN.BASE.BROWSER.001", "浏览器劫持"},
    {"WIN.PERSIST.PSPROFILE.001", "PowerShell 配置文件持久化"},
    {"WIN.PERSIST.LNKTARGET.001", "快捷方式指向可疑目标"},
    {"WIN.BASE.UAC.001", "UAC 已关闭"},
    {"WIN.BASE.BLANKPWD.001", "空口令可网络登录"},
    {"WIN.BASE.DEFSHARE.001", "默认管理共享未关"},
    {"WIN.RMT.SOFTWARE.001", "远控软件痕迹"},
    {"WIN.RMT.SUNLOGIN.RCE.001", "向日葵 RCE 痕迹"},
    {"WIN.TRACE.PREFETCH.001", "Prefetch 可疑程序"},
    {"WIN.FW.WRITABLEAPP.001", "防火墙放行可写程序"},
    {"WIN.SHARE.NONDEFAULT.001", "非默认共享"},
    {"WIN.DRV.WRITABLE.001", "驱动落在可写路径"},
    {"LNX.ACC.UID0.001", "非 root 的 UID 0 账户"},
    {"LNX.ACC.DUPUID.001", "重复 UID"},
    {"LNX.ACC.GID0.001", "GID 0 含非 root 成员"},
    {"LNX.ACC.SUDOERS.001", "sudoers NOPASSWD ALL"},
    {"LNX.ACC.SHADOWPERM.001", "shadow 权限过宽"},
    {"LNX.SSH.CONFIG.001", "sshd PermitRootLogin yes"},
    {"LNX.SSH.PWDAUTH.001", "sshd 允许口令登录"},
    {"LNX.SSH.MAXAUTH.001", "sshd MaxAuthTries 过大"},
    {"LNX.SSH.AUTHKEY.001", "authorized_keys 异常项"},
    {"LNX.SSH.PROXYCMD.001", "SSH ProxyCommand 后门"},
    {"LNX.SSH.PRIVKEY.001", "异常私钥文件"},
    {"LNX.SSH.HIDDENKEY.001", "点开头隐藏密钥"},
    {"LNX.PERSIST.CRON.001", "cron 可疑任务"},
    {"LNX.PERSIST.PROFILE.001", "profile/bashrc 后门"},
    {"LNX.PERSIST.PRELOAD.001", "ld.so.preload 非空"},
    {"LNX.HOSTS.LOOPBACK.001", "hosts 回环绑陌生名"},
    {"LNX.HOSTS.MAP.001", "hosts 非默认映射"},
    {"LNX.TRACE.HISTORY.001", "bash_history 可疑命令"},
    {"LNX.PERSIST.SYSTEMD.001", "systemd 单元可疑 Exec"},
    {"LNX.PERSIST.RCLOCAL.001", "rc.local 可疑行"},
    {"LNX.PROC.MINER.001", "疑似挖矿进程"},
    {"LNX.PROC.DELETED.001", "进程 exe 已删除"},
    {"LNX.SUID.UNEXPECTED.001", "意外 SUID 文件"},
    {"LNX.LOG.AUTHFAIL.001", "SSH 爆破 Top IP"},
    {"LNX.CAPS.UNEXPECTED.001", "非常规 capabilities"},
    {"LNX.PERSIST.AT.001", "at 队列可疑"},
    {"LNX.TIMER.FACT.001", "systemd timer 事实项"},
    {"LNX.FILES.DOUBLEEXT.001", "双扩展名伪装文件"},
    {"LNX.FILES.BASELINE.001", "基线文件内容不一致"},
    {"LNX.FILES.BASELINE.MISS.001", "基线文件缺失"},
    {"LNX.WEB.SHELL.001", "疑似 webshell"},
    {"LNX.WEB.LOGPOST.001", "Web 日志 POST Top IP"},
    {"LNX.WEB.LOGATTACK.001", "Web 日志攻击特征"},
    {"LNX.LDSO.INJECT.001", "ld.so.conf.d 注入"},
    {"LNX.WEB.CONFIGBACKDOOR.001", "Web 配置后门"},
    {"LNX.WEB.BLACKLINK.001", "网页黑链/黑页"},
    {"LNX.LOG.BTMP.001", "btmp 失败登录"},
    {"LNX.BASE.EMPTYPWD.001", "账户空口令"},
    {"LNX.BASE.WEAKPWD.001", "弱口令哈希"},
    {"LNX.BASE.PWDMAX.001", "密码最长有效期过长"},
    {"LNX.BASE.PWDLEN.001", "密码最小长度过短"},
    {"LNX.BASE.UMASK.001", "umask 过宽"},
    {"LNX.BASE.TMOUT.001", "会话无 TMOUT"},
    {"LNX.BASE.FAILLOCK.001", "登录失败未锁定"},
    {"LNX.PERSIST.PAM.001", "PAM 后门"},
    {"LNX.BASE.SYSACCT.001", "系统账户可登录"},
    {"LNX.BASE.KPARAM.001", "危险内核参数"},
    {"LNX.BASE.SELINUX.001", "SELinux 非强制"},
    {"LNX.BASE.APPARMOR.001", "AppArmor 无 profile"},
    {"LNX.BASE.KCVE.001", "内核已知漏洞特征"},
    {"LNX.BASE.KCVE.002", "内核已知漏洞特征"},
    {"LNX.BASE.UNSAFESVC.001", "危险服务在跑"},
    {"LNX.BASE.SNMP.001", "SNMP 默认团体名"},
    {"LNX.BASE.ENVPATH.001", "PATH 含可写目录"},
    {"MID.REDIS.NOPASS.001", "Redis 无密码"},
    {"MID.REDIS.BINDALL.001", "Redis 监听 0.0.0.0"},
    {"MID.MYSQL.UDF.001", "MySQL UDF 提权"},
    {"MID.MYSQL.ERRSHELL.001", "MySQL error.log 反弹 shell"},
    {"MID.PHP.PHPINFO.001", "phpinfo 暴露"},
    {"MID.WEB.GITLEAK.001", "Web 根 .git 泄露"},
    {"LNX.BASE.DROPRIGHT.001", "中间件未降权"},
    {"LNX.BASE.TRUST.EQUIV.001", "hosts.equiv 信任"},
    {"LNX.BASE.TRUST.RHOSTS.001", ".rhosts 信任"},
    {"LNX.BASE.ROOTPATH.001", "root PATH 异常"},
    {"LNX.BASE.FILEPERM.001", "关键文件权限过宽"},
    {"LNX.BASE.GRUBPWD.001", "GRUB 无口令"},
    {"LNX.BASE.CAD.001", "Ctrl-Alt-Del 可重启"},
    {"LNX.BASE.COREDUMP.001", "coredump 配置过宽"},
    {"LNX.BASE.NFS.001", "NFS 导出过宽"},
    {"LNX.BASE.HOSTSALLOW.001", "hosts.allow 过宽"},
    {"LNX.PROC.TMPDIR.001", "进程从临时目录运行"},
    {"LNX.PERSIST.XDG.001", "XDG autostart 持久化"},
    {"LNX.PERSIST.PYHOOK.001", "Python sitecustomize 钩子"},
    {"LNX.PERSIST.BASHFUNC.001", "bashrc 函数后门"},
    {"LNX.PERSIST.UDEV.001", "udev 规则持久化"},
    {"LNX.RANSOM.TRACE.001", "勒索痕迹"},
    {"LNX.RANSOM.SCRIPT.001", "勒索脚本"},
    {"LNX.TOOLS.ARTIFACT.001", "攻击工具残留"},
    {"LNX.TOOLS.FRPCFG.001", "frp/nps 配置残留"},
    {"LNX.PERSIST.SSHLOG.001", "SSH 明文口令记录后门"},
    {"LNX.BASE.CMDSIZE.001", "系统命令体积异常"},
    {"LNX.BASE.CMDRECENT.001", "系统命令近期被改"},
    {"LNX.SSH.PORT.001", "sshd 非默认端口"},
    {"LNX.BASE.RECENT.001", "近期新增可执行文件"},
    {"LNX.PROC.NAMEMISMATCH.001", "进程名与 exe 不符"},
    {"MID.MYSQL.LOGSHELL.001", "MySQL 日志写马"},
    {"MID.MYSQL.SLOWLOG.001", "MySQL slow log 写马"},
    {"MID.MYSQL.BINLOG.001", "MySQL binlog 明文取证"},
    {"MID.WEB.CREDS.001", "Web 根敏感凭据"},
};

static std::string utf8_clip(const std::string& s, size_t max_chars) {
    size_t i = 0, chars = 0;
    while (i < s.size() && chars < max_chars) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t w = 1;
        if ((c & 0x80) == 0) w = 1;
        else if ((c & 0xE0) == 0xC0) w = 2;
        else if ((c & 0xF0) == 0xE0) w = 3;
        else if ((c & 0xF8) == 0xF0) w = 4;
        if (i + w > s.size()) break;
        i += w;
        ++chars;
    }
    return s.substr(0, i);
}

std::string title_zh_of(const Finding& f) {
    for (const auto& row : kTitles)
        if (f.rule_id == row.id) return row.title;
    if (!f.rationale.empty()) {
        std::string r = f.rationale;
        size_t cut = r.find("：");
        if (cut == std::string::npos) cut = r.find(':');
        if (cut != std::string::npos && cut > 0 && cut < 40) r = r.substr(0, cut);
        return utf8_clip(r, 24);
    }
    return f.rule_id;
}

Triage triage_of(const Finding& f) {
    Triage t;
    t.bucket = bucket_of(f);
    t.bucket_id = bucket_id(t.bucket);
    t.bucket_zh = bucket_zh(t.bucket);
    t.title_zh = title_zh_of(f);
    t.default_visible = (t.bucket != Bucket::Inventory);
    return t;
}

ViewPreset parse_view_preset(const std::string& s) {
    if (s == "all" || s == "全部") return ViewPreset::All;
    if (s == "team" || s == "团队综合") return ViewPreset::Team;
    return ViewPreset::Personal;
}

bool finding_visible(const Finding& f, ViewPreset view,
                     const std::string& cat, const std::string& sev,
                     const std::string& query) {
    Triage t = triage_of(f);
    if (view != ViewPreset::All && !t.default_visible) return false;
    if (!cat.empty() && cat != "all" && cat != "全部" && cat != t.bucket_id && cat != t.bucket_zh)
        return false;
    if (!sev.empty() && sev != "all" && sev != "全部" && f.severity != sev)
        return false;
    if (!query.empty()) {
        auto hit = [&](const std::string& s) {
            return s.find(query) != std::string::npos || contains_ci(s, query);
        };
        if (!hit(t.title_zh) && !hit(f.rule_id) && !hit(f.object_ref) && !hit(f.rationale))
            return false;
    }
    return true;
}

std::vector<std::size_t> sorted_finding_indices(const std::vector<Finding>& fds) {
    std::vector<std::size_t> idx(fds.size());
    for (std::size_t i = 0; i < fds.size(); ++i) idx[i] = i;
    std::stable_sort(idx.begin(), idx.end(), [&](std::size_t a, std::size_t b) {
        const Finding& fa = fds[a];
        const Finding& fb = fds[b];
        int ba = bucket_rank(bucket_of(fa));
        int bb = bucket_rank(bucket_of(fb));
        if (ba != bb) return ba < bb;
        int sa = severity_rank(fa.severity);
        int sb = severity_rank(fb.severity);
        if (sa != sb) return sa < sb;
        int ca = confidence_rank(fa.confidence);
        int cb = confidence_rank(fb.confidence);
        if (ca != cb) return ca < cb;
        if (fa.rule_id != fb.rule_id) return fa.rule_id < fb.rule_id;
        return fa.object_ref < fb.object_ref;
    });
    return idx;
}

KpiCounts count_kpi(const std::vector<Finding>& fds) {
    KpiCounts k;
    k.total = static_cast<int>(fds.size());
    for (const auto& f : fds) {
        switch (bucket_of(f)) {
        case Bucket::Clear: ++k.clear; break;
        case Bucket::Harden: ++k.harden; break;
        case Bucket::Trace: ++k.trace; break;
        case Bucket::Web: ++k.web; break;
        case Bucket::Inventory: ++k.inventory; break;
        }
    }
    return k;
}

} // namespace ctfir
