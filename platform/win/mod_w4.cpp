// Windows 基线核查模块族（v0.4）：密码策略 / 账户口令状态 / RDP / SMBv1 / 自动登录 /
// 补丁留证 / 日志保留 / 高危端口监听。依据等保基线检查项 + 决赛指南"安全基线核查"考点。
#include "win_common.hpp"

#include <winsock2.h>
#include <iphlpapi.h>
#include <lm.h>
#include <tlhelp32.h>
#include <map>
#include <set>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ctfir::win {

namespace {

// ---- WIN.BASE.PASSWORD：密码策略（NetUserModalsGet）----
void mod_base_password(ModuleCtx& ctx) {
    USER_MODALS_INFO_0* u1 = nullptr;
    NET_API_STATUS st = NetUserModalsGet(nullptr, 0, (LPBYTE*)&u1);
    if (st != NERR_Success) {
        ctx.omitted_source("NetUserModalsGet(0)", last_error_str("NetUserModalsGet"));
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    DWORD minlen = u1->usrmod0_min_passwd_len;
    DWORD maxage = u1->usrmod0_max_passwd_age;
    DWORD minage = u1->usrmod0_min_passwd_age;
    NetApiBufferFree(u1);
    USER_MODALS_INFO_3* u3 = nullptr;
    DWORD lockout_thr = 0, have3 = 0;
    if (NetUserModalsGet(nullptr, 3, (LPBYTE*)&u3) == NERR_Success) {
        lockout_thr = u3->usrmod3_lockout_threshold;
        have3 = 1;
        NetApiBufferFree(u3);
    }
    Evidence e;
    e.source_kind = "api";
    e.source_path = "NetUserModalsGet(1/3) 密码策略";
    e.payload = "最小密码长度=" + std::to_string(minlen) +
                " 最长使用期=" + std::to_string(maxage / 86400) + " 天" +
                " 最短使用期=" + std::to_string(minage / 86400) + " 天" +
                (have3 ? " 锁定阈值=" + std::to_string(lockout_thr) + " 次失败" : "");
    ctx.add_evidence(e);
    ctx.checked_source("密码策略");
    if (minlen < 8) {
        Finding f;
        f.rule_id = "WIN.BASE.PWDLEN.001";
        f.severity = "medium";
        f.confidence = "high";
        f.rationale = "密码最小长度 " + std::to_string(minlen) + " 位（基线建议 ≥8）——弱口令/爆破面扩大";
        f.object_ref = "NetUserModalsGet";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }
    if (have3 && lockout_thr == 0) {
        Finding f;
        f.rule_id = "WIN.BASE.LOCKOUT.001";
        f.severity = "low";
        f.confidence = "high";
        f.rationale = "账户锁定阈值未启用（0）——爆破无锁定限制";
        f.object_ref = "NetUserModalsGet";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.BASE.ACCOUNTS：空密码/不需要密码账户 + Guest 状态 ----
void mod_base_accounts(ModuleCtx& ctx) {
    LPUSER_INFO_3 buf = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    if (NetUserEnum(nullptr, 3, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&buf,
                    MAX_PREFERRED_LENGTH, &read, &total, &resume) != NERR_Success) {
        ctx.omitted_source("NetUserEnum(口令状态)", last_error_str("NetUserEnum"));
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    for (DWORD i = 0; i < read; ++i) {
        USER_INFO_3& u = buf[i];
        std::string name = wide_to_utf8(u.usri3_name);
        if (u.usri3_flags & UF_PASSWD_NOTREQD) {
            Finding f;
            f.rule_id = "WIN.BASE.NOPASSWD.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "账户 \"" + name + "\" 标记为\"不需要密码\"（UF_PASSWD_NOTREQD）——"
                          "可能存在空口令，可直接登录的账面风险";
            f.object_ref = "NetUserEnum:" + name;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }
    // Guest 启用状态（RID 501）
    for (DWORD i = 0; i < read; ++i) {
        if (buf[i].usri3_user_id == 501) {
            if (!(buf[i].usri3_flags & UF_ACCOUNTDISABLE)) {
                Finding f;
                f.rule_id = "WIN.BASE.GUEST.001";
                f.severity = "medium";
                f.confidence = "high";
                f.rationale = "Guest 账户处于启用状态（基线建议禁用）";
                f.object_ref = "NetUserEnum:Guest";
                f.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(f);
            }
            break;
        }
    }
    NetApiBufferFree(buf);
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.BASE.RDP / SMB / AUTOLOGON / LOGPOLICY ----
void mod_base_reg(ModuleCtx& ctx) {
    // RDP：开启状态 + NLA + 端口
    std::string deny;
    reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            L"fDenyTSConnections", false, deny);
    std::string nla, port;
    reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            L"UserAuthentication", false, nla);
    reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            L"PortNumber", false, port);
    Evidence e;
    e.source_kind = "registry";
    e.source_path = "Terminal Server (RDP)";
    e.payload = "RDP启用=" + std::string(deny == "0" ? "是" : "否") + " NLA=" + nla + " 端口=" + port;
    ctx.add_evidence(e);
    ctx.checked_source("RDP 配置");
    if (deny == "0" && nla == "0") {
        Finding f;
        f.rule_id = "WIN.BASE.RDP.NONLA.001";
        f.severity = "medium";
        f.confidence = "high";
        f.rationale = "RDP 已启用且未强制 NLA（网络级身份验证）——爆破与漏洞（如 BlueKeep）暴露面";
        f.object_ref = "Terminal Server\\RDP-Tcp";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }
    if (!port.empty() && port != "3389")
        ctx.note("RDP 端口已改为 " + port + "（非默认，注意连接方式）");

    // SMBv1
    std::string smb1;
    reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            L"SMB1", false, smb1);
    if (smb1 == "1") {
        Finding f;
        f.rule_id = "WIN.BASE.SMB1.001";
        f.severity = "high";
        f.confidence = "high";
        f.rationale = "SMBv1 已启用（EternalBlue/ WannaCry 级暴露面）";
        f.object_ref = "LanmanServer\\Parameters\\SMB1";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    } else {
        ctx.checked_source("SMB1 [未启用或未显式设置]");
    }

    // 自动登录（凭据明文风险）
    std::string al;
    reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            L"AutoAdminLogon", false, al);
    std::string alpwd;
    reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            L"DefaultPassword", false, alpwd);
    if (al == "1") {
        Finding f;
        f.rule_id = "WIN.BASE.AUTOLOGON.001";
        f.severity = "high";
        f.confidence = "high";
        f.rationale = "已配置 Windows 自动登录（AutoAdminLogon=1）" +
                      std::string(alpwd.empty() ? "" : " 且 DefaultPassword 明文存在于注册表") +
                      "——凭据泄露风险";
        f.object_ref = "Winlogon\\AutoAdminLogon";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }

    // 登录界面不显示最后用户名（基线缺失项，low）
    std::string ddu;
    reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            L"DontDisplayLastUserName", false, ddu);
    if (ddu == "0" || ddu.empty())
        ctx.note("基线提示：登录界面显示最后登录用户名（DontDisplayLastUserName 未启用）");

    // 日志保留策略
    for (const wchar_t* ch : {L"Application", L"System", L"Security"}) {
        std::string ch8 = wide_to_utf8(ch);
        std::string ret;
        reg_get(HKEY_LOCAL_MACHINE,
                std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\") + ch,
                L"Retention", false, ret);
        if (ret == "0") {
            Finding f;
            f.rule_id = "WIN.BASE.LOGRET.001";
            f.severity = "low";
            f.confidence = "high";
            f.rationale = std::string("事件日志通道 ") + ch8 + " 保留策略为\"按需覆盖\"（Retention=0）——日志可被快速冲掉";
            f.object_ref = std::string("EventLog\\") + ch8;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }

    // 补丁留证（UBR + HotFix 计数）
    {
        std::string ubr;
        reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR", false, ubr);
        HKEY h = open_key(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix", false);
        int hf = 0;
        if (h) {
            hf = static_cast<int>(reg_subkeys(h).size());
            RegCloseKey(h);
        }
        Evidence pe;
        pe.source_kind = "registry";
        pe.source_path = "补丁信息（UBR + HotFix）";
        pe.payload = "UBR=" + ubr + " HotFix条目=" + std::to_string(hf) +
                     "（补丁详情建议 `wmic qfe list` 人工核对缺失补丁）";
        ctx.add_evidence(pe);
        ctx.checked_source("补丁留证");
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.BASE.PORTS：监听端口白名单核查（高危/多余服务暴露面）----
void mod_base_ports(ModuleCtx& ctx) {
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
    std::vector<BYTE> buf(sz ? sz : 1);
    if (GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) != NO_ERROR) {
        ctx.omitted_source("TCP 表(基线核查)", "获取失败");
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_MODULE*>(buf.data());
    // 常见合法监听端口白名单（比赛环境以业务为准，白名单外列低级线索）
        static const std::set<int> common = {21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                                             873, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
                                             5900, 6379, 7547, 8009, 8080, 8081, 8443, 9000, 11211,
                                             27017, 49152, 49153, 49154, 49155, 49156, 49157,
                                             49158, 49159, 49160}; // RPC 动态端口段起点
    std::string listing, unusual;
    int listen = 0;
    std::map<DWORD, std::string> pid_ports; // 复用 PID→端口，供进程名关联
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    std::map<DWORD, std::string> pname;
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{sizeof(pe)};
        if (Process32FirstW(snap, &pe)) {
            do { pname[pe.th32ProcessID] = wide_to_utf8(pe.szExeFile); } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    for (DWORD i = 0; i < t->dwNumEntries && i < 500; ++i) {
        auto& r = t->table[i];
        if (r.dwState != MIB_TCP_STATE_LISTEN) continue;
        int lp = ntohs((u_short)(r.dwLocalPort & 0xFFFF));
        ++listen;
        char b[48];
        std::snprintf(b, sizeof(b), "0.0.0.0:%d", lp);
        std::string who = pname.count(r.dwOwningPid) ? pname[r.dwOwningPid] : "?";
        pid_ports[r.dwOwningPid] += b;
        std::string row = std::string(b) + " ← " + who + " (PID " + std::to_string(r.dwOwningPid) + ")";
        listing += row + "\n";
        // 数据库/中间件服务绑 0.0.0.0 → 暴露面
        bool db = (lp == 3306 || lp == 6379 || lp == 1433 || lp == 5432 || lp == 27017 || lp == 11211);
        if (db && r.dwRemoteAddr == 0) {
            Finding f;
            f.rule_id = "WIN.BASE.DBEXPOSE.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "数据库/中间件端口 " + std::to_string(lp) + " 对所有网卡监听（" + who +
                          "）——若口令弱或未授权访问则为高危暴露面";
            f.object_ref = row;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
        if (!common.count(lp) && lp != 0 && unusual.size() < 1200) unusual += row + "\n";
    }
    Evidence e;
    e.source_kind = "api";
    e.source_path = "TCP LISTEN 白名单核查";
    e.payload = "listening=" + std::to_string(listen) + "\n" + listing;
    ctx.add_evidence(e);
    ctx.checked_source("监听端口");
    if (!unusual.empty()) {
        Finding f;
        f.rule_id = "WIN.BASE.UNUSUALPORT.001";
        f.severity = "low";
        f.confidence = "low";
        f.rationale = "非常见端口监听（业务白名单外的暴露面，需人工确认归属）:\n" + unusual;
        f.object_ref = "TCP LISTEN";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_w4(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"WIN.BASE.PWD", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_password(c); }});
    mods.push_back({"WIN.BASE.ACC", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_accounts(c); }});
    mods.push_back({"WIN.BASE.REG", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_reg(c); }});
    mods.push_back({"WIN.BASE.PORTS", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_ports(c); }});
}

} // namespace ctfir::win
