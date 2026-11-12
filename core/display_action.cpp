#include "display_action.hpp"
#include "advice.hpp"
#include "remediate.hpp"
#include "util.hpp"

#include <sstream>

namespace ctfir {

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

static std::string account_of(const Finding& f) {
    const std::string& o = f.object_ref;
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
    if (starts_with(f.rule_id, "WIN.ACC.") || starts_with(f.rule_id, "LNX.ACC."))
        return after_last(o, ':');
    return {};
}

static std::string contest_persist() {
    return "决赛：持久化必须删除该对象，注释或改名通常不得分。先留证再操作。";
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
        if (name.empty() || ends_with(name, "$")) continue;
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
            return "删除 " + file + " 第 " + line + " 行（不要清空整个文件）；Windows 再执行 ipconfig /flushdns";
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
    } else if (rid == "WIN.FILES.DOUBLEEXT.001") {
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
            a.contest_note = "微软预装组件（IE/WMP 等），默认不要删。切「全部」可见。";
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
        a.command = "只记录时间线，禁止 wevtutil cl（清空日志毁证且通常不得分）";
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
        a.contest_note = "先放行 SSH/RDP/业务端口，再开防火墙。本工具不自动改防火墙。";
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
    }

    if (a.command.empty()) a.command = from_plan(f);

    if (a.command.empty()) {
        if (!obj.empty())
            a.command = "按手册人工处置（对象: " + obj + "）";
        else
            a.command = "按手册人工处置";
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
        return "（该发现未挂接建议：按证据人工复核；本工具不执行任何修改。）";
    return b;
}

std::string instantiate_advice(const Finding& f) {
    DisplayAction da = display_action(f);
    std::string out;
    if (!da.command.empty())
        out += "【一条命令】" + da.command + "\n";
    if (!da.contest_note.empty())
        out += "【" + da.contest_note + "】\n";
    out += instantiate_advice_body(f);
    return out;
}

void write_checklist(FILE* fp, const std::vector<Finding>& fds, int limit) {
    if (!fp) return;
    KpiCounts k = count_kpi(fds);
    std::fprintf(fp, "[处置清单] 立刻清 %d  再加固 %d  溯源 %d  Web %d  隐藏清单 %d  合计 %d\n",
                 k.clear, k.harden, k.trace, k.web, k.inventory, k.total);
    auto idx = sorted_finding_indices(fds);
    int shown = 0, n = 0;
    for (auto i : idx) {
        const Finding& f = fds[i];
        Triage t = triage_of(f);
        if (!t.default_visible) continue;
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
