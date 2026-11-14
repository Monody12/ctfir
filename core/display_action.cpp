#include "display_action.hpp"
#include "advice.hpp"
#include "remediate.hpp"
#include "util.hpp"

#include <cstring>
#include <sstream>

namespace ctfir {

// Findings contain attacker-controlled names. Refuse to interpolate shell syntax.
static bool safe_command_object(const std::string& s, bool win) {
    const std::string bad = win ? "\"\r\n&|<>^%!" : "\"'`$\r\n;&|<>";
    return s.find_first_of(bad) == std::string::npos;
}

static std::string after_last(const std::string& s, char sep) {
    size_t p = s.rfind(sep);
    return p == std::string::npos ? s : s.substr(p + 1);
}

static std::string after_tok(const std::string& s, const std::string& tok) {
    size_t p = s.rfind(tok);
    return p == std::string::npos ? std::string() : s.substr(p + tok.size());
}

static std::string before_last(const std::string& s, char sep) {
    size_t p = s.rfind(sep);
    return p == std::string::npos ? s : s.substr(0, p);
}

static bool is_persist_rule(const std::string& rid) {
    return rid.find("AUTORUN") != std::string::npos ||
           rid.find("PERSIST") != std::string::npos ||
           rid.find("TASK.SUSPECT") != std::string::npos ||
           rid.find("HOSTS") != std::string::npos ||
           rid.find("PRELOAD") != std::string::npos ||
           rid.find("CRON") != std::string::npos ||
           rid.find("IFEO") != std::string::npos ||
           rid.find("LOGONSCRIPT") != std::string::npos ||
           rid.find("PORTPROXY") != std::string::npos ||
           rid.find("AD.GPP") != std::string::npos ||
           rid.find("AD.NTDS") != std::string::npos ||
           rid.find("AD.IFM") != std::string::npos ||
           rid.find("AD.SYSVOL") != std::string::npos ||
           rid.find("AD.GPO") != std::string::npos;
}

static bool is_digits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (c < '0' || c > '9') return false;
    return true;
}

static std::string path_of_ref(const std::string& obj) {
    size_t p = obj.rfind(':');
    if (p == std::string::npos || p == 0) return obj;
    if (is_digits(obj.substr(p + 1))) return obj.substr(0, p);
    return obj;
}

static std::string line_of_ref(const std::string& obj) {
    size_t p = obj.rfind(':');
    if (p == std::string::npos) return {};
    std::string a = obj.substr(p + 1);
    return is_digits(a) ? a : std::string();
}

static std::string account_of(const Finding& f) {
    const std::string& o = f.object_ref;
    const std::string& rid = f.rule_id;
    if (starts_with(o, "NetUserEnum:")) return o.substr(12);
    if (starts_with(o, "Administrators:")) {
        std::string n = o.substr(15);
        size_t p = n.find('\\');
        if (p != std::string::npos) n = n.substr(p + 1);
        return n;
    }
    if (o.find("UserList\\") != std::string::npos) return after_last(o, '\\');
    if (starts_with(o, "/etc/passwd:") || starts_with(o, "/etc/shadow:"))
        return after_last(o, ':');
    if (rid == "LNX.ACC.UID0.001" || rid == "LNX.ACC.DUPUID.001" ||
        rid == "LNX.BASE.EMPTYPWD.001" || rid == "LNX.BASE.SYSACCT.001" ||
        rid == "LNX.BASE.WEAKPWD.001")
        return after_last(o, ':');
    if (starts_with(rid, "WIN.ACC.")) {
        std::string n = after_last(o, ':');
        if (n == "NetUserEnum" || n == "Shares") return {};
        return n;
    }
    if (rid == "LNX.ACC.GID0.001" && starts_with(o, "/etc/group:"))
        return after_last(o, ':');
    return {};
}

static std::string contest_persist() {
    return "这条要删掉，注释或改名经常不算。先拷走再删。";
}

static bool is_win_path(const std::string& s) {
    return s.size() >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) &&
           s[1] == ':' && (s[2] == '\\' || s[2] == '/');
}

static std::string share_commands(const Finding& f) {
    std::string out;
    for (const auto& ln : split_lines(f.rationale)) {
        size_t p = ln.find(" \xE2\x86\x92 "); // UTF-8 →
        if (p == std::string::npos) p = ln.find(" -> ");
        if (p == std::string::npos) continue;
        std::string name = trim(ln.substr(0, p));
        if (name.empty() || ends_with(name, "$") || !safe_command_object(name, true)) continue;
        if (!out.empty()) out += "\r\n";
        out += "net share \"" + name + "\" /delete";
    }
    if (out.empty()) {
        std::string n = f.object_ref;
        if (starts_with(n, "Shares:")) n = n.substr(7);
        if (!n.empty() && n != "Shares")
            out = "net share \"" + n + "\" /delete";
    }
    return out;
}

static std::string ads_del_cmd(const std::string& obj) {
    std::string p = obj;
    if (ends_with(p, ":$DATA")) p = p.substr(0, p.size() - 6);
    if (!is_win_path(p)) return {};
    size_t colon = p.find(':', 2);
    if (colon == std::string::npos || colon + 1 >= p.size()) return {};
    std::string file = p.substr(0, colon);
    std::string stream = p.substr(colon + 1);
    return "del \"" + file + ":" + stream + "\"";
}

static std::string from_plan(const Finding& f) {
    RemediationPlan p = plan_remediation(f);
    if (!p.supported) return {};
    if (!p.steps.empty()) {
        // 展示清除步骤（最后一条）；跳过内部 __LNX_*__ 标记
        for (auto it = p.steps.rbegin(); it != p.steps.rend(); ++it) {
            if (it->find("__LNX_") == 0) continue;
            return *it;
        }
    }
    if (!p.native_ops.empty()) {
        const std::string& op = p.native_ops[0];
        if (starts_with(op, "hosts_delete_line:")) {
            std::string spec = op.substr(18);
            std::string file = before_last(spec, ':');
            std::string line = after_last(spec, ':');
            if (file.find("/etc/hosts") != std::string::npos)
                return "sed -i '" + line + "d' \"" + file + "\"";
            return "notepad \"" + file + "\"\r\n# 只删第 " + line + " 行，不要清空文件\r\nipconfig /flushdns";
        }
        if (starts_with(op, "linux_comment_line:")) {
            std::string spec = op.substr(19);
            std::string file = before_last(spec, ':');
            std::string line = after_last(spec, ':');
            return "sed -i '" + line + "d' \"" + file + "\"";
        }
        if (starts_with(op, "quarantine:")) {
            std::string path = op.substr(11);
            return "mv \"" + path + "\" \"" + path + ".ctfir-quarantine\"";
        }
    }
    return {};
}

DisplayAction display_action(const Finding& f) {
    DisplayAction a;
    Triage t = triage_of(f);
    a.title = t.title_zh;
    a.bucket = t.bucket;
    if (is_persist_rule(f.rule_id)) a.contest_note = contest_persist();

    const std::string& rid = f.rule_id;
    const std::string& obj = f.object_ref;
    std::string acct = account_of(f);
    if (!safe_command_object(obj, starts_with(rid, "WIN."))) {
        a.contest_note = "对象含 shell 特殊字符：仅留证，不生成可复制执行命令";
        return a;
    }

    if (t.bucket == Bucket::Inventory) {
        a.command = "无需删除，仅供对照";
        a.contest_note.clear();
        return a;
    }

    if (rid == "WIN.ACC.DOLLAR.001" || rid == "WIN.ACC.CUSTOM.001") {
        if (!acct.empty())
            a.command = "net user \"" + acct + "\" /delete";
    } else if (rid == "WIN.ACC.ADMIN.001") {
        if (!acct.empty())
            a.command = "net localgroup Administrators \"" + acct + "\" /delete";
    } else if (rid == "WIN.ACC.GUESTADMIN.001") {
        a.command = "net localgroup Administrators Guest /delete\r\nnet user Guest /active:no";
    } else if (rid == "WIN.ACC.LOGIN_HIDE.001") {
        std::string name = after_last(obj, '\\');
        a.command = "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v \"" +
                    name + "\" /f";
    } else if (rid == "WIN.AUTORUN.IFEO.001") {
        std::string exe = after_tok(obj, "IFEO\\");
        if (exe.empty()) exe = after_last(obj, '\\');
        a.command = "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" +
                    exe + "\" /v Debugger /f";
    } else if (rid == "WIN.AUTORUN.LOGONSCRIPT.001") {
        a.command = "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v UserInitMprLogonScript /f";
    } else if (rid == "WIN.AUTORUN.APPINIT.001") {
        a.command =
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v AppInit_DLLs /t REG_SZ /d \"\" /f\r\n"
            "reg add \"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v AppInit_DLLs /t REG_SZ /d \"\" /f\r\n"
            "# 依据里的 .dll 先拷走再 del";
    } else if (rid == "WIN.AUTORUN.SUSPECT.001" || rid == "WIN.AUTORUN.REFPATH.001") {
        if (is_win_path(obj)) {
            a.command = "del /f \"" + obj + "\"";
        } else {
            std::string name = after_last(obj, '\\');
            if (name.empty()) name = obj;
            a.command =
                "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" + name + "\" /f\r\n"
                "reg delete \"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" + name + "\" /f\r\n"
                "reg delete \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" + name + "\" /f";
        }
    } else if (rid == "WIN.SVC.SUSPECT.001") {
        std::string name = after_tok(obj, "Services\\");
        if (name.empty()) name = after_last(obj, '\\');
        a.command = "sc stop \"" + name + "\"\r\nsc config \"" + name + "\" start= disabled\r\nsc delete \"" + name + "\"";
    } else if (rid == "WIN.TASK.SUSPECT.001") {
        std::string tn = after_tok(obj, "Task\\");
        if (tn.empty()) tn = after_last(obj, '\\');
        if (!tn.empty() && tn[0] != '\\') tn = "\\" + tn;
        a.command = "schtasks /end /tn \"" + tn + "\"\r\nschtasks /delete /tn \"" + tn + "\" /f";
    } else if (rid == "WIN.TRACE.PSHIST.001") {
        a.command = "findstr /n /i /c:\"IEX\" /c:\"-enc\" /c:\"DownloadString\" \"" + path_of_ref(obj) +
                    "\"\r\n# 历史是线索，不要删整个文件";
        a.contest_note.clear();
    } else if (rid == "WIN.RMT.SOFTWARE.001") {
        a.command = "dir /s /b \"" + obj + "\"\r\n# 题面要求卸载就卸；目录可 rd /s /q \"" + obj + "\"";
        a.contest_note.clear();
    } else if (rid == "WIN.RANSOM.TRACE.001") {
        a.command = "mkdir %TEMP%\\ransom-evidence 2>nul\r\ncopy /y \"" + obj +
                    "\" %TEMP%\\ransom-evidence\\\r\ndel /f \"" + obj + "\"";
    } else if (rid == "LNX.RANSOM.TRACE.001" || rid == "LNX.RANSOM.SCRIPT.001") {
        a.command = "cp \"" + obj + "\" /tmp/ransom-evidence-$(basename \"" + obj + "\")\nrm -f \"" + obj + "\"";
    } else if (rid == "WIN.HOSTS.MAP.001" || rid == "WIN.HOSTS.LOOPBACK.001") {
        std::string ln = line_of_ref(obj);
        a.command = "notepad \"" + path_of_ref(obj) + "\"\r\n# 只删第 " +
                    (ln.empty() ? "命中" : ln) + " 行，不要清空文件\r\nipconfig /flushdns";
    } else if (rid == "LNX.HOSTS.MAP.001" || rid == "LNX.HOSTS.LOOPBACK.001") {
        std::string ln = line_of_ref(obj);
        a.command = "sed -i '" + (ln.empty() ? "Nd" : ln + "d") + "' /etc/hosts";
    } else if (rid == "LNX.PERSIST.CRON.001") {
        std::string file = path_of_ref(obj);
        std::string ln = line_of_ref(obj);
        if (file.find("cron.d") != std::string::npos)
            a.command = "rm -f \"" + file + "\"";
        else if (!ln.empty())
            a.command = "sed -i '" + ln + "d' \"" + file + "\"";
        else
            a.command = "crontab -l";
    } else if (rid == "LNX.PERSIST.AT.001") {
        a.command = "rm -f \"" + path_of_ref(obj) + "\"";
    } else if (rid == "LNX.BASE.PWDMAX.001") {
        a.command = "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs";
        a.contest_note.clear();
    } else if (rid == "LNX.BASE.PWDLEN.001") {
        a.command = "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    8/' /etc/login.defs";
        a.contest_note.clear();
    } else if (rid == "LNX.BASE.TMOUT.001") {
        a.command = "grep -q '^TMOUT=' /etc/profile || echo 'TMOUT=300' >> /etc/profile";
        a.contest_note.clear();
    } else if (rid == "LNX.BASE.UMASK.001") {
        std::string file = path_of_ref(obj);
        std::string ln = line_of_ref(obj);
        if (!ln.empty())
            a.command = "sed -i '" + ln + "s/umask .*/umask 027/' \"" + file + "\"";
        else
            a.command = "sed -i 's/umask 0[0-9][0-9]/umask 027/' \"" + file + "\"";
        a.contest_note.clear();
    } else if (rid == "LNX.BASE.FAILLOCK.001") {
        a.command = "grep -n faillock /etc/pam.d/* /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | head\n"
                    "# CentOS 7 可加: auth required pam_tally2.so deny=5 unlock_time=600 even_deny_root";
        a.contest_note.clear();
    } else if (rid == "LNX.BASE.KPARAM.001") {
        if (obj.find("ip_forward") != std::string::npos)
            a.command = "sysctl -w net.ipv4.ip_forward=0";
        else if (obj.find("dmesg_restrict") != std::string::npos)
            a.command = "sysctl -w kernel.dmesg_restrict=1";
        else {
            std::string key = obj;
            if (starts_with(key, "/proc/sys/")) key = key.substr(10);
            for (char& c : key) if (c == '/') c = '.';
            a.command = "sysctl -w " + key + "=<按题面>";
        }
        a.contest_note.clear();
    } else if (rid == "LNX.BASE.CAD.001") {
        a.command = "systemctl mask ctrl-alt-del.target 2>/dev/null || rm -f /etc/init/control-alt-delete.conf";
        a.contest_note.clear();
    } else if (rid == "LNX.BASE.COREDUMP.001") {
        a.command = "grep -q 'hard core' /etc/security/limits.conf || echo '* hard core 0' >> /etc/security/limits.conf";
        a.contest_note.clear();
    } else if (rid == "LNX.BASE.DROPRIGHT.001") {
        std::string pid = after_tok(obj, "PID ");
        if (pid.empty()) pid = "<pid>";
        a.command = "ps -o user,pid,cmd -p " + pid + "\n# 中间件不要用 root 跑，改 User= 后重启";
        a.contest_note.clear();
    } else if (rid == "MID.MYSQL.LOGSHELL.001" || rid == "MID.MYSQL.ERRSHELL.001" ||
               rid == "MID.MYSQL.UDF.001") {
        a.command = "mv \"" + path_of_ref(obj) + "\" \"" + path_of_ref(obj) + ".quarantine\"";
    } else if (rid == "MID.MYSQL.SLOWLOG.001" || rid == "MID.MYSQL.BINLOG.001") {
        std::string logf = path_of_ref(obj);
        if (is_win_path(logf))
            a.command = "findstr /i \"OUTFILE sys_eval sys_exec\" \"" + logf + "\"\r\n# 日志是线索，不要删";
        else
            a.command = "grep -nE 'OUTFILE|sys_eval|sys_exec' \"" + logf + "\" | head\n# 日志是线索，不要删";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.UAC.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.BLANKPWD.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.DEFSHARE.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v AutoShareWks /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.GUEST.001") {
        a.command = "net user Guest /active:no";
        a.contest_note.clear();
    } else if (rid == "WIN.FILES.ADS.001") {
        a.command = ads_del_cmd(obj);
        if (a.command.empty())
            a.command = "del \"" + obj + "\"   （Win7 用 del 文件:流名，不要用 PowerShell -Stream）";
    } else if (rid == "WIN.FILES.DOUBLEEXT.001" || rid == "WIN.FILES.TEMPEXE.001" ||
               rid == "WIN.WEB.WEBSHELL.001" ||
               rid == "WIN.TOOLS.ARTIFACT.001" || rid == "WIN.TOOLS.FRPCFG.001") {
        a.command = "del /f \"" + obj + "\"";
    } else if (rid == "WIN.BASE.PWDLEN.001") {
        a.command = "net accounts /minpwlen:8";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.LOCKOUT.001") {
        a.command = "net accounts /lockoutthreshold:5";
        a.contest_note.clear();
    } else if (rid == "WIN.AUDIT.DISABLED.001") {
        a.command = "auditpol /set /category:* /success:enable /failure:enable";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.AUTOLOGON.001") {
        a.command =
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_SZ /d 0 /f\r\n"
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword /f";
        a.contest_note = "先留证 DefaultPassword，再关自动登录并删明文口令。";
    } else if (rid == "WIN.SHARE.NONDEFAULT.001") {
        a.command = share_commands(f);
    } else if (rid == "WIN.PORTPROXY.001") {
        std::string spec = after_tok(obj, "tcp\\");
        if (spec.empty()) spec = after_tok(obj, "udp\\");
        if (spec.empty()) spec = after_last(obj, '\\');
        size_t sl = spec.rfind('/');
        if (sl != std::string::npos) {
            std::string addr = spec.substr(0, sl);
            std::string port = spec.substr(sl + 1);
            a.command = "netsh interface portproxy delete v4tov4 listenport=" + port +
                        " listenaddress=" + addr;
        }
    } else if (rid == "WIN.BASE.ACTIVESETUP.001") {
        std::string guid = after_tok(obj, "ActiveSetup\\");
        if (guid.empty()) guid = after_last(obj, '\\');
        if (!guid.empty() && guid[0] == '>') guid = guid.substr(1);
        a.command = "reg query \"HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" +
                    guid + "\" /v StubPath";
        if (is_known_ms_activesetup(obj)) {
            a.contest_note = "微软预装组件（IE/WMP），一般不用删。";
        } else {
            a.command += "\r\nreg delete \"HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" +
                         guid + "\" /f";
        }
    } else if (rid == "WIN.BASE.NOPASSWD.001") {
        if (acct == "Administrator")
            a.command = "net user Administrator   （核实空口令；赛场禁止改 Administrator 密码时只写入报告）";
        else if (acct == "Guest")
            a.command = "net user Guest /active:no";
        else if (!acct.empty())
            a.command = "net user \"" + acct + "\" /active:no";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.LOGRET.001") {
        std::string ch = after_last(obj, '\\');
        if (ch.empty()) ch = "Application";
        a.command = "wevtutil sl " + ch + " /ms:104857600";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.UNUSUALPORT.001") {
        a.command = "netstat -ano 对照 PID；先留证，不要直接杀进程";
        a.contest_note.clear();
    } else if (rid.find(".EVT.") != std::string::npos) {
        a.command = "记下时间线，不要 wevtutil cl（清日志既毁证也经常不得分）";
        a.contest_note.clear();
    } else if (starts_with(rid, "WIN.AUTORUN.") && is_win_path(obj)) {
        a.command = "del /f \"" + obj + "\"";
    } else if (rid == "WIN.AD.GPP.CPASSWORD.001" || rid == "WIN.AD.NTDS.COPY.001" ||
               rid == "WIN.AD.IFM.001" || rid == "WIN.AD.SYSVOL.SCRIPT.001" ||
               rid == "WIN.AD.GPO.TASK.001" || rid == "WIN.AD.GPO.SCRIPTINI.001" ||
               rid == "WIN.AD.GPO.DELEG.001" || rid == "WIN.AD.GPP.ADMIN.001" ||
               rid == "WIN.AD.GPP.REG.001" || rid == "WIN.AD.GPP.FILE.001" ||
               rid == "WIN.AD.GPP.SVC.001" || rid == "WIN.AD.HIVE.COPY.001" ||
               rid == "WIN.AD.LSASS.DMP.001") {
        if (is_win_path(obj))
            a.command = "del /f \"" + obj + "\"";
        a.contest_note = "先复制到证据目录再删。cpassword/哈希不要解密入库。";
    } else if (rid == "WIN.AD.DSRM.LOGON.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v DsrmAdminLogonBehavior /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.AD.LDAP.NOSIGN.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.AD.SPOOLER.DC.001") {
        a.command = "sc stop Spooler\r\nsc config Spooler start= disabled";
        a.contest_note = "仅域控/无打印需求的服务器执行；工作站误报不要关。";
    } else if (rid == "WIN.AD.SMBSIGN.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v RequireSecuritySignature /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.WDIGEST.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.NTLMV1.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.LATFP.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.NOLMHASH.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v NoLmHash /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.RESTRICTANON.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.EVERYONEANON.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.PLAINSMB.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.PNP.ELEV.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.ALWAYSINST.001") {
        a.command =
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f\r\n"
            "reg add \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.WINRM.UNENC.001") {
        a.command =
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v AllowUnencrypted /t REG_DWORD /d 0 /f\r\n"
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v AllowBasic /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.FW.OFF.001") {
        a.command = "netsh advfirewall set allprofiles state on";
        a.contest_note = "先放行 SSH/RDP/业务端口，再开防火墙。";
    } else if (rid == "WIN.BASE.PWDHIST.001") {
        a.command = "net accounts /uniquepw:5";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.PWDAGE.001") {
        a.command = "net accounts /maxpwage:42";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.LASTUSER.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DontDisplayLastUserName /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.RDP.NONLA.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.SMB1.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v SMB1 /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.AD.MACHPWD.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v DisablePasswordChange /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.SEALCHAN.001") {
        a.command =
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SealSecureChannel /t REG_DWORD /d 1 /f\r\n"
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v RequireSignOrSeal /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.LDAPCLIENT.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP\" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.AD.LDAP.BIND.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.UAC.NOPROMPT.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.DISABLECAD.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableCAD /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.PNP.ADMIN.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.RDP.SECLAYER.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v SecurityLayer /t REG_DWORD /d 2 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.CACHEDLOGON.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v CachedLogonsCount /t REG_SZ /d 10 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.FORCELOGOFF.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v enableforcedlogoff /t REG_DWORD /d 1 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.NTLMSEC.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NtlmMinClientSec /t REG_DWORD /d 537395200 /f";
        a.contest_note = "537395200 = 0x20080000（NTLMv2 session + 128-bit）";
    } else if (rid == "WIN.BASE.PS.UNRESTRICT.001") {
        a.command = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\" /v ExecutionPolicy /t REG_SZ /d Restricted /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.RDP.ENCRYPT.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v MinEncryptionLevel /t REG_DWORD /d 3 /f";
        a.contest_note.clear();
    } else if (rid == "WIN.BASE.REMOTEREG.001") {
        a.command = "sc config RemoteRegistry start= disabled";
        a.contest_note = "不要在还需要远程注册表管理的机器上禁用。";
    } else if (rid == "WIN.BASE.FORCEGUEST.001") {
        a.command = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v ForceGuest /t REG_DWORD /d 0 /f";
        a.contest_note.clear();
    } else if (rid == "LNX.ACC.UID0.001" || rid == "LNX.ACC.DUPUID.001" ||
               rid == "LNX.BASE.EMPTYPWD.001" || rid == "LNX.BASE.SYSACCT.001") {
        if (!acct.empty() && acct != "root")
            a.command = "usermod -L \"" + acct + "\"\n# 家目录不是 /、/tmp、/var 再：userdel \"" + acct + "\"";
        else
            a.command = "grep -n ':0:' /etc/passwd\n# 非 root 的 UID=0 先 usermod -L";
    } else if (rid == "LNX.ACC.SUDOERS.001") {
        std::string file = path_of_ref(obj);
        std::string ln = line_of_ref(obj);
        if (file.find("sudoers.d") != std::string::npos)
            a.command = "rm -f \"" + file + "\"";
        else if (!ln.empty())
            a.command = "sed -i '" + ln + "d' \"" + file + "\"";
        else
            a.command = "visudo -c\n# 删掉 NOPASSWD: ALL 那一行，不要清空整个 sudoers";
    } else if (rid == "LNX.ACC.GID0.001") {
        std::string g = after_last(obj, ':');
        if (g.empty()) g = acct;
        a.command = "sed -i '/^" + g + ":/d' /etc/group";
    } else if (rid == "LNX.SSH.CONFIG.001") {
        a.command = "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\nsshd -t && (systemctl reload sshd 2>/dev/null || service sshd reload)";
    } else if (rid == "LNX.SSH.PWDAUTH.001") {
        a.command = "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\nsshd -t && (systemctl reload sshd 2>/dev/null || service sshd reload)";
    } else if (rid == "LNX.SSH.PORT.001" || rid == "LNX.SSH.MAXAUTH.001") {
        std::string ln = line_of_ref(obj);
        std::string file = path_of_ref(obj);
        if (file.empty()) file = "/etc/ssh/sshd_config";
        if (!ln.empty())
            a.command = "sed -i '" + ln + "d' \"" + file + "\"\n# 多余 Port 删掉，保留 22\nsshd -t && (systemctl reload sshd 2>/dev/null || service sshd reload)";
        else
            a.command = "grep -n '^Port ' /etc/ssh/sshd_config\n# 只留 22";
    } else if (rid == "LNX.SSH.AUTHKEY.001") {
        std::string file = obj.empty() ? "~/.ssh/authorized_keys" : obj;
        a.command = "cp \"" + file + "\" \"" + file + ".bak\"\n# 打开文件，一行一把钥匙，多出来的删掉，chmod 600";
    } else if (rid == "LNX.SSH.HIDDENKEY.001") {
        a.command = "rm -f \"" + obj + "\"";
    } else if (rid == "LNX.SSH.PROXYCMD.001") {
        std::string file = path_of_ref(obj);
        std::string ln = line_of_ref(obj);
        if (!ln.empty())
            a.command = "sed -i '" + ln + "d' \"" + file + "\"";
        else
            a.command = "rm -f \"" + file + "\"";
    } else if (rid == "LNX.PERSIST.PRELOAD.001") {
        a.command = "cp /etc/ld.so.preload /tmp/ld.so.preload.bak 2>/dev/null; : > /etc/ld.so.preload\n# 对应 .so 先拷走再删";
    } else if (rid == "LNX.PERSIST.RCLOCAL.001") {
        std::string ln = line_of_ref(obj);
        a.command = "sed -i '" + (ln.empty() ? "1d" : ln + "d") + "' /etc/rc.local";
    } else if (rid == "LNX.LDSO.INJECT.001") {
        a.command = "rm -f \"" + path_of_ref(obj) + "\"";
    } else if (rid == "LNX.TRACE.HISTORY.001") {
        a.command = "sed -n '" + (line_of_ref(obj).empty() ? "1" : line_of_ref(obj)) +
                    "p' \"" + path_of_ref(obj) + "\"\n# 这是线索，顺着 IP/文件追，不要清空 history";
        a.contest_note.clear();
    } else if (rid == "LNX.PERSIST.XINETD.001") {
        a.command = "rm -f \"" + path_of_ref(obj) + "\"";
    } else if (rid == "LNX.FILES.DOUBLEEXT.001" || rid == "LNX.TOOLS.ARTIFACT.001" ||
               rid == "LNX.TOOLS.FRPCFG.001" || rid == "LNX.PERSIST.SSHLOG.001" ||
               rid == "LNX.PERSIST.XDG.001" || rid == "LNX.PERSIST.PYHOOK.001" ||
               rid == "LNX.PERSIST.UDEV.001") {
        a.command = "rm -f \"" + path_of_ref(obj) + "\"";
    } else if (rid == "LNX.WEB.SHELL.001" ||
               rid == "MID.PHP.PHPINFO.001" || rid == "MID.WEB.CREDS.001" ||
               rid == "MID.WEB.GITLEAK.001" || rid == "MID.WEB.BACKUP.001") {
        a.command = "mv \"" + obj + "\" \"" + obj + ".quarantine\"";
    } else if (rid == "LNX.WEB.BLACKLINK.001" || rid == "WIN.WEB.BLACKLINK.001") {
        std::string base = after_last(obj, '/');
        if (base.find('\\') != std::string::npos) base = after_last(obj, '\\');
        std::string blow = to_lower(base);
        if (blow == "index.php" || blow == "index.html" || blow == "index.htm" ||
            blow == "index.asp" || blow == "index.aspx" || blow == "default.asp" ||
            blow == "default.aspx")
            a.command = "打开 \"" + obj + "\" 把隐藏的 <a>/<iframe> 黑链删掉，首页不要整份移走";
        else if (is_win_path(obj) || starts_with(rid, "WIN."))
            a.command = "del /f \"" + obj + "\"";
        else
            a.command = "mv \"" + obj + "\" \"" + obj + ".quarantine\"";
    } else if (rid == "MID.REDIS.NOPASS.001") {
        a.command = "sed -i 's/^bind .*/bind 127.0.0.1/' \"" + obj + "\"\necho 'requirepass 换成强口令' >> \"" + obj + "\"";
    } else if (rid == "MID.REDIS.BINDALL.001") {
        a.command = "sed -i 's/^bind .*/bind 127.0.0.1/' \"" + obj + "\"";
    } else if (rid == "MID.REDIS.PROTMODE.001") {
        a.command = "sed -i 's/^protected-mode.*/protected-mode yes/' \"" + path_of_ref(obj) + "\"";
    } else if (rid == "LNX.ACC.SHADOWPERM.001") {
        a.command = "chmod 000 /etc/shadow";
    } else if (rid == "LNX.PERSIST.INITD.001") {
        std::string initf = path_of_ref(obj);
        a.command = "rm -f \"" + initf + "\"\nchkconfig --del $(basename \"" + initf + "\") 2>/dev/null || true";
    } else if (rid == "LNX.PERSIST.SYSTEMD.001" || rid == "LNX.TIMER.FACT.001") {
        std::string unit = path_of_ref(obj);
        a.command = "systemctl disable --now $(basename \"" + unit + "\") 2>/dev/null\nmv \"" + unit +
                    "\" \"" + unit + ".quarantine\"\nsystemctl daemon-reload";
    } else if (rid == "LNX.WEB.LOGPOST.001" || rid == "LNX.WEB.LOGATTACK.001" ||
               rid == "LNX.LOG.AUTHFAIL.001" || rid == "WIN.WEB.LOGPOST.001" ||
               rid == "WIN.WEB.LOGATTACK.001") {
        a.command = "把 Top IP 和时间写进报告，不要清日志";
        a.contest_note.clear();
    }

    if (starts_with(rid, "LNX.PROC.")) {
        std::string pid = after_tok(obj, "PID ");
        a.command = is_digits(pid) ? "ps -p " + pid + " -o pid,ppid,comm,args\nreadlink /proc/" + pid + "/exe" : "只读复核当前进程身份；不要按过期 PID 终止进程";
        a.contest_note = "只读复核，不生成 STOP/KILL；PID 1 和系统服务尤其不能盲目终止。";
    }
    if (a.command.empty()) a.command = from_plan(f);

    if (a.command.empty() && starts_with(rid, "LNX.")) {
        if (rid.find("CAPS") != std::string::npos) {
            a.command = "getcap \"" + obj + "\"\n# ping/mtr/newuidmap 是发行版自带，不用动；确认异常再 setcap -r \"" + obj + "\"";
        } else if (rid.find("SUID") != std::string::npos) {
            a.command = "ls -l \"" + obj + "\"\nchmod u-s \"" + obj + "\"";
        } else if (rid.find("TMPDIR") != std::string::npos || rid.find("PROC.DELETED") != std::string::npos ||
                   rid.find("NAMEMISMATCH") != std::string::npos || rid.find("PROC.MINER") != std::string::npos) {
            std::string pid = after_tok(obj, "PID ");
            if (pid.empty()) pid = "<pid>";
            a.command = "ls -l /proc/" + pid + "/exe";
        } else if (rid.find("HOSTS") != std::string::npos) {
            std::string line = line_of_ref(obj);
            a.command = "sed -i '" + (line.empty() ? "Nd" : line + "d") + "' /etc/hosts";
        } else if (rid.find("CMDSIZE") != std::string::npos) {
            a.command = "rpm -V coreutils 2>/dev/null || dpkg -V coreutils\n# 先拷走再 yum reinstall / apt install --reinstall";
        } else if (rid.find("XINETD") != std::string::npos) {
            a.command = "rm -f \"" + path_of_ref(obj) + "\"";
        } else if (rid.find("PAM") != std::string::npos) {
            std::string file = path_of_ref(obj);
            std::string ln = line_of_ref(obj);
            if (!ln.empty())
                a.command = "sed -i '" + ln + "d' \"" + file + "\"";
            else
                a.command = "rm -f \"" + file + "\"";
        } else if (rid.find("BASHFUNC") != std::string::npos || rid.find("PROFILE") != std::string::npos) {
            std::string file = path_of_ref(obj);
            std::string ln = line_of_ref(obj);
            if (!ln.empty())
                a.command = "sed -i '" + ln + "d' \"" + file + "\"";
            else
                a.command = "打开 \"" + file + "\" 把 alias/函数那几行删掉";
        }
    }

    if (a.command.empty()) {
        if (!obj.empty())
            a.command = "打开 " + obj + " 看原文，确认后再动手。";
        else
            a.command = "打开这条的位置看原文，确认后再动手。";
    }
    return a;
}

static void replace_all(std::string& s, const std::string& from, const std::string& to) {
    if (from.empty() || to.empty()) return;
    size_t p = 0;
    while ((p = s.find(from, p)) != std::string::npos) {
        s.replace(p, from.size(), to);
        p += to.size();
    }
}

static std::string filled_advice_text(const Finding& f) {
    const Advice* adv = find_advice(f.advice_id);
    if (!adv) return {};
    std::string body = adv->text;
    std::string acct = account_of(f);
    bool linux = starts_with(f.rule_id, "LNX.") || starts_with(f.rule_id, "MID.");
    bool win = starts_with(f.rule_id, "WIN.");
    if (linux || win) {
        std::string filtered;
        bool skip = false;
        auto strip = [](const std::string& line, const char* pfx) {
            return trim(line.substr(std::strlen(pfx)));
        };
        for (const auto& line : split_lines(body)) {
            std::string shown = line;
            if (starts_with(line, "Windows：")) {
                skip = linux;
                shown = strip(line, "Windows：");
            } else if (starts_with(line, "Windows:")) {
                skip = linux;
                shown = strip(line, "Windows:");
            } else if (starts_with(line, "Linux：")) {
                skip = win;
                shown = strip(line, "Linux：");
            } else if (starts_with(line, "Linux:")) {
                skip = win;
                shown = strip(line, "Linux:");
            }
            if (skip) continue;
            if (!filtered.empty()) filtered += "\n";
            filtered += shown;
        }
        if (!filtered.empty()) body = filtered;
    }
    std::string task = after_tok(f.object_ref, "Task");
    std::string svc = after_tok(f.object_ref, "Services\\");
    if (svc.empty() && f.rule_id.find("SVC") != std::string::npos)
        svc = after_last(f.object_ref, '\\');
    std::string pid = after_tok(f.object_ref, "PID ");
    std::string key = f.object_ref;
    std::string vname = after_last(f.object_ref, '\\');
    if (!acct.empty()) {
        replace_all(body, "<账户名>", acct);
        replace_all(body, "<用户名>", acct);
    } else {
        replace_all(body, "net user <账户名> 看组。", "用 net user 看组。");
        replace_all(body, "id <用户名>。", "用 id 看 UID。");
        replace_all(body, "<账户名>", "该账户");
        replace_all(body, "<用户名>", "该用户");
    }
    if (!task.empty()) replace_all(body, "<任务路径>", task);
    if (!svc.empty()) replace_all(body, "<服务名>", svc);
    if (!pid.empty()) replace_all(body, "<pid>", pid);
    if (!key.empty()) replace_all(body, "<精确键路径>", key);
    if (!vname.empty()) replace_all(body, "<值名>", vname);
    replace_all(body, "<键>", key);
    return std::string("【") + adv->title + "】\n" + body;
}

std::string instantiate_advice_body(const Finding& f) {
    std::string b = filled_advice_text(f);
    if (b.empty())
        return "打开这条的位置看原文，确认后再动手。";
    return b;
}

std::string instantiate_advice(const Finding& f) {
    DisplayAction da = display_action(f);
    std::string out;
    if (!da.command.empty())
        out += "【一条命令】" + da.command + "\n";
    out += instantiate_advice_body(f);
    return out;
}

void write_checklist(FILE* fp, const std::vector<Finding>& fds, int limit) {
    if (!fp) return;
    KpiCounts k = count_kpi(fds);
    std::fprintf(fp, "[处置清单] 先清 %d  Web %d  溯源 %d  加固 %d  清单 %d  合计 %d\n",
                 k.clear, k.web, k.trace, k.harden, k.inventory, k.total);
    auto idx = sorted_finding_indices(fds);
    int shown = 0, n = 0;
    for (auto i : idx) {
        const Finding& f = fds[i];
        Triage t = triage_of(f);
        ++n;
        if (shown >= limit) continue;
        DisplayAction da = display_action(f);
        std::fprintf(fp, "%2d. [%s/%s] %s  %s\n    %s\n",
                     n, t.bucket_zh, f.severity.c_str(), da.title.c_str(),
                     f.object_ref.c_str(), da.command.c_str());
        ++shown;
    }
    if (n > shown)
        std::fprintf(fp, "  … 其余 %d 条见报告 HTML\n", n - shown);
}

} // namespace ctfir
