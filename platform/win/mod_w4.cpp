// Windows 基线核查模块族（v0.4）：密码策略 / 账户口令状态 / RDP / SMBv1 / 自动登录 /
// 补丁留证 / 日志保留 / 高危端口监听。依据等保基线检查项 + 决赛指南"安全基线核查"考点。
#include "win_common.hpp"
#include "core/log_attack.hpp"
#include <cstdlib>

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
    DWORD hist = u1->usrmod0_password_hist_len;
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
                " 最长使用期=" + (maxage == 0xFFFFFFFFu ? std::string("无限") :
                                 std::to_string(maxage / 86400) + " 天") +
                " 最短使用期=" + std::to_string(minage / 86400) + " 天" +
                " 历史=" + std::to_string(hist) +
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
    if (hist == 0) {
        Finding f;
        f.rule_id = "WIN.BASE.PWDHIST.001";
        f.severity = "low";
        f.confidence = "high";
        f.rationale = "密码历史长度为 0（可立即重用旧口令）。技能赛常见要求 ≥5";
        f.object_ref = "NetUserModalsGet";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }
    if (maxage == 0xFFFFFFFFu) {
        Finding f;
        f.rule_id = "WIN.BASE.PWDAGE.001";
        f.severity = "low";
        f.confidence = "high";
        f.rationale = "密码最长使用期限为无限（不过期）。技能赛常见要求 30–45 天";
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

    // 登录界面不显示最后用户名（技能赛/等保高频项）
    std::string ddu;
    reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            L"DontDisplayLastUserName", false, ddu);
    if (ddu == "0" || ddu.empty()) {
        Finding f;
        f.rule_id = "WIN.BASE.LASTUSER.001";
        f.severity = "low";
        f.confidence = "high";
        f.rationale = "登录界面显示最后登录用户名（DontDisplayLastUserName 未启用）——减少账户枚举成本";
        f.object_ref = "Policies\\System\\DontDisplayLastUserName";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }

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

// ---- WIN.BASE.WMI / BITS / COM / WINLOGON-SCR ----
void mod_base_persist(ModuleCtx& ctx) {
    // 1) WMI 事件订阅持久化（__EventFilter + CommandLineEventConsumer）
    {
        std::string sub;
        bool found = false;
        // 命名空间枚举（只读两个最常用路径）
        for (const wchar_t* ns : {L"ROOT\\Subscription", L"ROOT\\CIMV2"}) {
            HKEY h = nullptr;
            // WMI 对象不存注册表；用 process 检查 eventconsumer 进程痕迹
            // 实际持久化通过 WMI repo 文件（objects.data）→ 只能通过 COM 枚举
            // 轻量替代：检查可疑的 wmiprvse.exe 加载异常 + 注册表宿主
        }
        // 注册表方式的 WMI 持久化（通过 __FilterToConsumerBinding 的活动脚本）
        // 用 WMI COM 查询（已在 PROCCMD 有 COM 基础）
        // 简化：检查常见持久化路径
        for (const char* script : {"C:\\Windows\\System32\\wbem\\mof\\",
                                    "C:\\Windows\\Temp\\"}) {
            WIN32_FIND_DATAA fd;
            HANDLE fh = FindFirstFileA((std::string(script) + "*").c_str(), &fd);
            if (fh != INVALID_HANDLE_VALUE) {
                do {
                    std::string fn = to_lower(fd.cFileName);
                    if (ends_with(fn, ".mof") && fn.find("cli_") != std::string::npos) {
                        Finding f;
                        f.rule_id = "WIN.BASE.WMICONSUMER.001";
                        f.severity = "high";
                        f.confidence = "medium";
                        f.rationale = "可疑 MOF 文件（WMI 持久化痕迹）: " +
                                      std::string(script) + fd.cFileName;
                        f.object_ref = std::string(script) + fd.cFileName;
                        f.advice_id = "ADVICE.TASK.REVIEW.001";
                        ctx.add_finding(f);
                        found = true;
                    }
                } while (FindNextFileA(fh, &fd));
                FindClose(fh);
            }
        }
        if (!found) ctx.checked_source("WMI MOF 痕迹 [clean]");
        ctx.note("WMI 事件订阅 COM 枚举需完整 COM 初始化——建议结合 Get-WmiObject 人工复查");
    }

    // 2) BITS 任务枚举（后门下载器持久化）
    {
        // BITS 任务存储在注册表 + QMGR 数据库——检查注册表残留
        HKEY h = open_key(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BITS", false);
        if (h) { RegCloseKey(h); }
        // 检查 bitsadmin 相关服务
        std::string bits_state;
        reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\BITS",
                L"Start", false, bits_state);
        ctx.checked_source("BITS 服务状态");
        ctx.note("BITS 任务枚举需 bitsadmin /list 命令——建议人工执行");
    }

    // 3) COM 劫持（HKCU CLSID InprocServer32 指向不存在/可疑 DLL）
    {
        const std::wstring base = L"Software\\Classes\\CLSID";
        HKEY hkcu = open_key(HKEY_CURRENT_USER, base, false);
        if (hkcu) {
            int checked = 0, hijacked = 0;
            for (const auto& clsid : reg_subkeys(hkcu)) {
                if (++checked > 500) break;
                if (ctx.expired()) break;
                std::string dll;
                if (reg_get(HKEY_CURRENT_USER, base + L"\\" + clsid + L"\\InprocServer32",
                            L"", false, dll)) {
                    if (dll.empty() || !file_exists(dll)) continue;
                    if (is_writable_path(dll)) {
                        ++hijacked;
                        if (hijacked <= 5) {
                            Finding f;
                            f.rule_id = "WIN.BASE.COMHIJACK.001";
                            f.severity = "medium";
                            f.confidence = "medium";
                            f.rationale = "COM 劫持痕迹（HKCU InprocServer32 指向可写路径 DLL）: " +
                                          wide_to_utf8(clsid) + " → " + dll.substr(0, 150);
                            f.object_ref = "HKCU\\" + wide_to_utf8(clsid);
                            f.advice_id = "ADVICE.HARDEN.001";
                            ctx.add_finding(f);
                        }
                    }
                }
            }
            RegCloseKey(hkcu);
            ctx.checked_source("HKCU COM 劫持（" + std::to_string(checked) + " CLSID）");
        }
    }

    // 4) 屏幕保护后门（SCR 替换）
    {
        std::string scr;
        reg_get(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"SCRNSAVE.EXE", false, scr);
        if (!scr.empty() && !is_expected_path(scr) && is_writable_path(scr)) {
            Finding f;
            f.rule_id = "WIN.BASE.SCRNSAVE.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "屏幕保护程序指向可写目录: " + scr.substr(0, 150) + "——SCR 后门";
            f.object_ref = "HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE";
            f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
            ctx.add_finding(f);
        }
    }

    // 5) SSH wrapper 后门（sshd 二进制哈希 vs 正常大小）
    {
        std::string sshd = sysroot() + "\\System32\\OpenSSH\\sshd.exe";
        if (file_exists(sshd)) {
            ctx.planned_source(sshd);
            ReadResult r = read_text_file(sshd, 32 * 1024 * 1024);
            if (r.ok) {
                Evidence e;
                e.source_kind = "file";
                e.source_path = sshd;
                e.sha256 = r.raw_sha256;
                e.payload = "(二进制留证) size=" + std::to_string(r.raw_size);
                ctx.add_evidence(e);
                ctx.checked_source("OpenSSH sshd.exe 哈希留证");
            }
        }
    }
    // 6) 服务 DLL 劫持（svchost 组服务的 ServiceDll 指向可写路径）
    {
        HKEY h = open_key(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\ServiceProvider\\ServiceTypes", false);
        if (h) RegCloseKey(h); // 探测
        // 遍历所有服务，找 svchost 调用的 ServiceDll
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (scm) {
            DWORD need = 0, count = 0, resume = 0;
            EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32_SHARE_PROCESS,
                                  SERVICE_STATE_ALL, nullptr, 0, &need, &count, &resume, nullptr);
            std::vector<BYTE> sbuf(need);
            if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32_SHARE_PROCESS,
                                      SERVICE_STATE_ALL, sbuf.data(), need, &need, &count, &resume, nullptr)) {
                auto* svc = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS*>(sbuf.data());
                int dll_checked = 0, dll_flagged = 0;
                for (DWORD i = 0; i < count && dll_checked < 100; ++i) {
                    if (ctx.expired()) break;
                    SC_HANDLE hsvc = OpenServiceW(scm, svc[i].lpServiceName, SERVICE_QUERY_CONFIG);
                    if (!hsvc) continue;
                    DWORD qn = 0;
                    QueryServiceConfigW(hsvc, nullptr, 0, &qn);
                    if (qn > 0 && qn < 1024 * 1024) {
                        std::vector<BYTE> qb(qn);
                        if (QueryServiceConfigW(hsvc, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(qb.data()), qn, &qn)) {
                            auto* qc = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(qb.data());
                            // svchost 共享进程的服务 → 查 ServiceDll
                            if (qc->lpBinaryPathName && contains_ci(wide_to_utf8(qc->lpBinaryPathName), "svchost")) {
                                std::string dllpath;
                                std::wstring param_key = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") +
                                                         svc[i].lpServiceName + L"\\Parameters";
                                reg_get(HKEY_LOCAL_MACHINE, param_key, L"ServiceDll", false, dllpath);
                                if (!dllpath.empty()) {
                                    ++dll_checked;
                                    if (is_writable_path(dllpath) && dll_flagged < 10) {
                                        ++dll_flagged;
                                        Finding f;
                                        f.rule_id = "WIN.BASE.SVCDLL.001";
                                        f.severity = "medium";
                                        f.confidence = "medium";
                                        f.rationale = "svchost 服务 ServiceDll 指向可写目录（DLL 劫持/后门）: " +
                                                      wide_to_utf8(svc[i].lpServiceName) + " → " + dllpath.substr(0, 150);
                                        f.object_ref = "ServiceDll\\" + wide_to_utf8(svc[i].lpServiceName);
                                        f.advice_id = "ADVICE.SVC.REVIEW.001";
                                        ctx.add_finding(f);
                                    }
                                }
                            }
                        }
                    }
                    CloseServiceHandle(hsvc);
                }
                ctx.checked_source("svchost ServiceDll 劫持（" + std::to_string(dll_checked) + " 项）");
            }
            CloseServiceHandle(scm);
        }
    }
    // 6b) Netsh portproxy 端口转发后门（T1090；netsh interface portproxy 持久化在注册表）
    {
        struct PpPath { const wchar_t* reg; const char* label; };
        static const PpPath proto_paths[] = {
            {L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4", "v4tov4"},
            {L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov6", "v4tov6"},
            {L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v6tov4", "v6tov4"},
            {L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v6tov6", "v6tov6"},
        };
        int pp_total = 0;
        for (const auto& e : proto_paths) {
            for (const wchar_t* proto : {L"tcp", L"udp"}) {
                std::wstring full = std::wstring(e.reg) + L"\\" + proto;
                HKEY h = open_key(HKEY_LOCAL_MACHINE, full, false);
                if (!h) continue;
                auto vals = reg_values(h);
                RegCloseKey(h);
                for (const auto& v : vals) {
                    ++pp_total;
                    if (pp_total <= 10) {
                        Finding f;
                        f.rule_id = "WIN.PORTPROXY.001";
                        f.severity = "medium";
                        f.confidence = "high";
                        f.rationale = "netsh portproxy 端口转发规则: " + v.name +
                                      " → " + v.data + "（可作内网穿透/流量中继后门）";
                        f.object_ref = std::string("PortProxy\\") + e.label + "\\" +
                                       wide_to_utf8(proto) + "\\" + v.name;
                        f.advice_id = "ADVICE.SVC.REVIEW.001";
                        ctx.add_finding(f);
                    }
                }
            }
        }
        if (pp_total == 0) ctx.checked_source("PortProxy 转发规则 [clean]");
        else ctx.checked_source("PortProxy 转发规则（" + std::to_string(pp_total) + " 条）");
    }
    // 7) Netsh Helper DLL (T1546.007)
    {
        std::string helpers;
        reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\NetSh", L"", false, helpers);
        // 枚举所有值
        HKEY h = open_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\NetSh", false);
        if (h) {
            auto vals = reg_values(h);
            RegCloseKey(h);
            for (const auto& v : vals) {
                if (v.data.empty()) continue;
                // NetSh helper 默认只有系统自带的几个 DLL
                if (is_writable_path(v.data)) {
                    Finding f;
                    f.rule_id = "WIN.BASE.NETSH.001";
                    f.severity = "high";
                    f.confidence = "medium";
                    f.rationale = "Netsh Helper DLL 指向可写路径（netsh 启动时自动加载）: " + v.name + " → " + v.data.substr(0, 150);
                    f.object_ref = "NetSh\\" + v.name;
                    f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
                    ctx.add_finding(f);
                }
            }
            ctx.checked_source("NetSh Helper DLL");
        }
    }

    // 8) Active Setup (T1547.014) — 用户登录时以管理员执行
    {
        const std::wstring as = L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components";
        HKEY h = open_key(HKEY_LOCAL_MACHINE, as, false);
        if (h) {
            for (const auto& clsid : reg_subkeys(h)) {
                std::string cmd;
                reg_get(HKEY_LOCAL_MACHINE, as + L"\\" + clsid, L"StubPath", false, cmd);
                if (cmd.empty()) continue;
                if (is_writable_path(cmd) || !is_expected_path(cmd)) {
                    Finding f;
                    f.rule_id = "WIN.BASE.ACTIVESETUP.001";
                    f.severity = "medium";
                    f.confidence = "medium";
                    f.rationale = "Active Setup StubPath 引用非常规路径（用户每次登录时以管理员执行）: " +
                                  wide_to_utf8(clsid) + " → " + cmd.substr(0, 150);
                    f.object_ref = "ActiveSetup\\" + wide_to_utf8(clsid);
                    f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
                    ctx.add_finding(f);
                }
            }
            RegCloseKey(h);
            ctx.checked_source("Active Setup StubPath");
        }
    }

    // 9) .NET CLR Profiler (T1574.012) — 环境变量持久化
    {
        std::string cor_prof, cor_path;
        reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                L"COR_ENABLE_PROFILING", false, cor_prof);
        reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                L"COR_PROFILER_PATH", false, cor_path);
        if (cor_prof == "1" && !cor_path.empty()) {
            Finding f;
            f.rule_id = "WIN.BASE.CORPROFILER.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = ".NET CLR Profiler 持久化（COR_ENABLE_PROFILING=1 + COR_PROFILER_PATH）: " + cor_path.substr(0, 150);
            f.object_ref = "COR_PROFILER_PATH";
            f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
            ctx.add_finding(f);
        }
    }

    // 10) Windows Defender 排除项（攻击者添加以免杀）
    {
        for (const wchar_t* excl_path : {
            L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
            L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions",
            L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
        }) {
            HKEY h = open_key(HKEY_LOCAL_MACHINE, excl_path, false);
            if (!h) continue;
            auto vals = reg_values(h);
            RegCloseKey(h);
            for (const auto& v : vals) {
                if (v.data == "0") continue; // 未启用
                Finding f;
                f.rule_id = "WIN.BASE.DEFEXCL.001";
                f.severity = "medium";
                f.confidence = "high";
                f.rationale = "Windows Defender 排除项（攻击者可利用以免杀）: " + v.name + " = " + v.data;
                f.object_ref = wide_to_utf8(excl_path) + "\\" + v.name;
                f.advice_id = "ADVICE.HARDEN.001";
                ctx.add_finding(f);
            }
            ctx.checked_source(wide_to_utf8(excl_path));
        }
    }

    // 11) Port Monitor DLL (T1547.010)
    {
        const std::wstring pm = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors";
        HKEY h = open_key(HKEY_LOCAL_MACHINE, pm, false);
        if (h) {
            for (const auto& mon : reg_subkeys(h)) {
                std::string driver;
                reg_get(HKEY_LOCAL_MACHINE, pm + L"\\" + mon, L"Driver", false, driver);
                if (driver.empty()) continue;
                if (is_writable_path(driver)) {
                    Finding f;
                    f.rule_id = "WIN.BASE.PORTMON.001";
                    f.severity = "high";
                    f.confidence = "medium";
                    f.rationale = "打印监控器 DLL 指向可写路径（Print Monitor 持久化）: " +
                                  wide_to_utf8(mon) + " → " + driver.substr(0, 150);
                    f.object_ref = "PrintMonitor\\" + wide_to_utf8(mon);
                    f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
                    ctx.add_finding(f);
                }
            }
            RegCloseKey(h);
            ctx.checked_source("Port Monitor DLL");
        }
    }

    // 12) 浏览器首页劫持
    {
        std::string start_page;
        reg_get(HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Main",
                L"Start Page", false, start_page);
        if (!start_page.empty()) {
            std::string low = to_lower(start_page);
            bool known = contains_ci(low, "bing.com") || contains_ci(low, "google.com") ||
                         contains_ci(low, "baidu.com") || contains_ci(low, "microsoft.com") ||
                         contains_ci(low, "about:blank");
            if (!known) {
                Finding f;
                f.rule_id = "WIN.BASE.BROWSER.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "浏览器首页被修改为非常见地址: " + start_page.substr(0, 150) + "（暗链/劫持线索）";
                f.object_ref = "IE Start Page";
                f.advice_id = "ADVICE.HOSTS.REVIEW.001";
                ctx.add_finding(f);
            }
        }
        ctx.checked_source("浏览器首页");
    }
    // 13) PowerShell Profile 持久化 (T1546.013)
    {
        // $PROFILE 路径（CurrentUserCurrentHost 最常用）
        char up[MAX_PATH]{};
        SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, up);
        std::string doc = std::string(up) + "\\Documents";
        // Win7 SP1+ 默认路径
        std::vector<std::string> profiles = {
            doc + "\\WindowsPowerShell\\profile.ps1",
            doc + "\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
            doc + "\\WindowsPowerShell\\Microsoft.PowerShellISE_profile.ps1",
        };
        // AllUsers 版本
        std::string windir = sysroot();
        profiles.push_back(windir + "\\System32\\WindowsPowerShell\\v1.0\\profile.ps1");
        profiles.push_back(windir + "\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1");

        for (const auto& pf : profiles) {
            ReadResult r = read_text_file(pf, 256 * 1024);
            if (!r.ok) continue;
            // 检查可疑内容
            bool sus = contains_ci(r.content, "invoke-expression") ||
                       contains_ci(r.content, "iex ") ||
                       contains_ci(r.content, "downloadstring") ||
                       contains_ci(r.content, "start-process") ||
                       contains_ci(r.content, "net.webclient") ||
                       contains_ci(r.content, "invoke-webrequest") ||
                       contains_ci(r.content, "certutil") ||
                       contains_ci(r.content, "encodedcommand");
            if (sus) {
                Finding f;
                f.rule_id = "WIN.PERSIST.PSPROFILE.001";
                f.severity = "high";
                f.confidence = "medium";
                f.rationale = "PowerShell Profile 含可疑命令（每次 PS 启动时自动执行）: " + pf.substr(0, 150);
                f.object_ref = pf;
                f.evidence_paths = {pf};
                f.advice_id = "ADVICE.PROFILE.REVIEW.001";
                ctx.add_finding(f);
            }
        }
        ctx.checked_source("PowerShell Profile（5 路径）");
    }

    // 14) Startup .lnk 目标检查 (T1547.009)
    {
        // Startup 文件夹中的 .lnk 文件，解析目标路径（不使用 COM 接口，读二进制找路径）
        char startup_path[MAX_PATH]{};
        if (SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, startup_path) == S_OK) {
            WIN32_FIND_DATAA fd;
            HANDLE fh = FindFirstFileA((std::string(startup_path) + "\\*.lnk").c_str(), &fd);
            if (fh != INVALID_HANDLE_VALUE) {
                do {
                    std::string lnk = std::string(startup_path) + "\\" + fd.cFileName;
                    std::string low = to_lower(lnk);
                    // 读取 .lnk 二进制，提取目标路径（Shell Link Header）
                    ReadResult r = read_text_file(lnk, 64 * 1024);
                    if (!r.ok) continue;
                    // LNK 文件中嵌入 UTF-16 或 ANSI 路径
                    std::string target;
                    size_t pos = r.content.find(":\\");
                    if (pos != std::string::npos && pos >= 1) {
                        // 向前找路径起点
                        size_t start = pos;
                        while (start > 0 && r.content[start - 1] != '\0' && r.content[start - 1] >= 32) start--;
                        // 向后找路径终点
                        size_t end = pos;
                        while (end < r.content.size() && r.content[end] != '\0' && r.content[end] >= 32) end++;
                        target = r.content.substr(start, end - start);
                    }
                    if (!target.empty() && is_writable_path(target)) {
                        Finding f;
                        f.rule_id = "WIN.PERSIST.LNKTARGET.001";
                        f.severity = "medium";
                        f.confidence = "medium";
                        f.rationale = "Startup .lnk 快捷方式指向可写路径: " + lnk + " → " + target.substr(0, 150);
                        f.object_ref = lnk;
                        f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
                        ctx.add_finding(f);
                    }
                } while (FindNextFileA(fh, &fd));
                FindClose(fh);
            }
            ctx.checked_source("Startup .lnk 目标检查");
        }
    }

    // 15) UAC / 空口令限制 / 默认共享 / 域成员（等保基线四项）
    {
        std::string v;
        // UAC（EnableLUA=0 → 提权提示完全失效）
        reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                L"EnableLUA", false, v);
        if (v == "0x0" || v == "0") {
            Finding f;
            f.rule_id = "WIN.BASE.UAC.001";
            f.severity = "medium";
            f.confidence = "high";
            f.rationale = "UAC 已完全禁用（EnableLUA=0）——恶意程序静默提权无拦截（等保基线项）";
            f.object_ref = "HKLM\\...\\Policies\\System\\EnableLUA";
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
        ctx.checked_source("UAC 状态");
        // 空口令远程限制（LimitBlankPasswordUse=0 → 空口令账户可远程登录）
        v.clear();
        reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"LimitBlankPasswordUse", false, v);
        if (v == "0x0" || v == "0") {
            Finding f;
            f.rule_id = "WIN.BASE.BLANKPWD.001";
            f.severity = "medium";
            f.confidence = "high";
            f.rationale = "空口令账户允许网络登录（LimitBlankPasswordUse=0）——配合空口令账户即可远程接管";
            f.object_ref = "HKLM\\SYSTEM\\...\\Lsa\\LimitBlankPasswordUse";
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
        ctx.checked_source("空口令网络限制");
        // 默认共享（AutoShareWks 缺省=1 开启；显式 0 才禁用——检测开启状态提示横移面）
        v.clear();
        reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                L"AutoShareWks", false, v);
        if (v.empty() || v == "0x1" || v == "1") {
            Finding f;
            f.rule_id = "WIN.BASE.DEFSHARE.001";
            f.severity = "low";
            f.confidence = "medium";
            f.rationale = "默认共享未禁用（C$/ADMIN$ 可用）——横移便利面；无共享需求建议 AutoShareWks=0";
            f.object_ref = "LanmanServer\\Parameters\\AutoShareWks";
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
        ctx.checked_source("默认共享状态");
        // 域成员判定（note：域环境提示横向/凭据传递考点）
        v.clear();
        reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                L"Domain", false, v);
        if (!v.empty() && to_lower(v) != "workgroup" && to_lower(v) != "wildpackets") {
            ctx.note("本机属于域: " + v + "——域环境注意域管账号/凭据传递/DSQuery 类考点（本工具不覆盖域枚举）");
        } else {
            ctx.note("本机为工作组/独立环境（无 Domain 值）");
        }
        ctx.checked_source("域成员状态");
    }

    // 16) 远控软件痕迹（玄机·向日葵整题；Sunlogin/ToDesk/TeamViewer/AnyDesk）
    {
        struct RcSoft { const char* dir; const char* name; const char* loghint; };
        static const RcSoft rcs[] = {
            {"C:\\Program Files\\Oray\\SunLogin", "向日葵(SunLogin)",
             "日志在 SunLogin\\SunloginClient\\log——RCE 案需查 PowerShell 路径遍历特征记录"},
            {"C:\\Program Files (x86)\\Oray\\SunLogin", "向日葵(SunLogin x86)",
             "日志在 SunLogin\\SunloginClient\\log"},
            {"C:\\Program Files\\ToDesk", "ToDesk", "日志在 ToDesk\\log"},
            {"C:\\Program Files\\TeamViewer", "TeamViewer", "日志 TeamViewerXX_Logfile.log"},
            {"C:\\Program Files (x86)\\TeamViewer", "TeamViewer x86", "日志 TeamViewerXX_Logfile.log"},
            {"C:\\Program Files\\AnyDesk", "AnyDesk", "痕迹 ad.trace / connection_trace.txt"},
        };
        int found_rc = 0;
        for (const auto& rc : rcs) {
            if (!dir_exists(rc.dir)) continue;
            ++found_rc;
            Finding f;
            f.rule_id = "WIN.RMT.SOFTWARE.001";
            f.severity = "low";
            f.confidence = "high";
            f.rationale = std::string("检测到远控软件: ") + rc.name + "（" + rc.dir +
                          "）——" + rc.loghint + "；向日葵曾爆 PowerShell 路径遍历 RCE（CNVD-2022-03661 类）";
            f.object_ref = rc.dir;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
            // 向日葵日志快速特征（RCE 攻击记录：日志含 WindowsPowerShell 路径遍历）
            if (std::string(rc.name).find("SunLogin") != std::string::npos) {
                std::string logdir = std::string(rc.dir) + "\\SunloginClient\\log";
                WIN32_FIND_DATAA fd;
                HANDLE fh = FindFirstFileA((logdir + "\\*.log").c_str(), &fd);
                if (fh != INVALID_HANDLE_VALUE) {
                    do {
                        std::string lp = logdir + "\\" + fd.cFileName;
                        ReadResult r = read_text_file(lp, 4 * 1024 * 1024);
                        if (!r.ok) continue;
                        if (r.content.find("WindowsPowerShell") != std::string::npos &&
                            r.content.find("..\\..\\") != std::string::npos) {
                            Finding f2;
                            f2.rule_id = "WIN.RMT.SUNLOGIN.RCE.001";
                            f2.severity = "high";
                            f2.confidence = "medium";
                            f2.rationale = "向日葵日志含路径遍历特征（WindowsPowerShell + ../../）: " +
                                           lp + "——疑似远控 RCE 攻击记录（首次出现时间≈攻击时间）";
                            f2.object_ref = lp;
                            f2.evidence_paths = {lp};
                            f2.advice_id = "ADVICE.EVENTLOG.REVIEW.001";
                            ctx.add_finding(f2);
                        }
                    } while (FindNextFileA(fh, &fd));
                    FindClose(fh);
                }
            }
        }
        if (found_rc == 0) ctx.checked_source("远控软件痕迹 [clean]");
        else ctx.checked_source("远控软件痕迹（" + std::to_string(found_rc) + " 款）");
    }

    ctx.set_status(ModuleStatus::PASS);
}

// ---- MID.MYSQL（Windows）：phpstudy / wamp / xampp / 官方路径的 general/slow/binlog 取证 ----
// 规则 ID 与 Linux 侧一致（MID.MYSQL.LOGSHELL / SLOWLOG / BINLOG），只扫明文关键字，不连库。
void mod_mysql_win(ModuleCtx& ctx) {
    std::vector<std::string> roots;
    const char* fx = std::getenv("CTFIR_FIXTURE_MYSQL");
    if (fx && *fx) {
        roots.push_back(fx);
        ctx.note("CTFIR_FIXTURE_MYSQL 已设置——附加扫描夹具根（测试用）");
    }
    const char* known[] = {
        "C:\\phpstudy_pro\\Extensions",
        "C:\\phpstudy\\MySQL",
        "C:\\phpstudy\\MYSQL",
        "C:\\phpstudy\\PHPTutorial\\MySQL",
        "C:\\phpstudy\\PHPTutorial\\MariaDB",
        "D:\\phpstudy_pro\\Extensions",
        "D:\\phpstudy\\MySQL",
        "D:\\phpstudy\\PHPTutorial\\MySQL",
        "C:\\wamp64\\bin\\mysql",
        "C:\\wamp\\bin\\mysql",
        "C:\\xampp\\mysql",
        "D:\\xampp\\mysql",
        "C:\\Program Files\\MySQL",
        "C:\\ProgramData\\MySQL",
        "C:\\Program Files\\MariaDB",
    };
    for (const char* k : known) roots.push_back(k);

    auto list_entries = [](const std::string& dir, bool dirs_only) {
        std::vector<std::string> out;
        WIN32_FIND_DATAA fd;
        HANDLE fh = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (fh == INVALID_HANDLE_VALUE) return out;
        do {
            if (fd.cFileName[0] == '.') continue;
            bool isdir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            if (dirs_only != isdir) continue;
            out.push_back(dir + "\\" + fd.cFileName);
        } while (FindNextFileA(fh, &fd));
        FindClose(fh);
        return out;
    };

    // 收集候选目录：根本身 + 一层子目录（MySQL5.7.26、mysql8.0.xx 等）
    std::vector<std::string> cands;
    for (const auto& r : roots) {
        if (!dir_exists(r)) continue;
        cands.push_back(r);
        for (const auto& sub : list_entries(r, true)) cands.push_back(sub);
    }

    std::vector<std::string> glogs, slogs, blogs, inis;
    auto push_unique = [](std::vector<std::string>& v, const std::string& p) {
        for (const auto& e : v) if (_stricmp(e.c_str(), p.c_str()) == 0) return;
        v.push_back(p);
    };

    auto classify_file = [&](const std::string& fp) {
        std::string low = to_lower(fp);
        std::string base = low;
        size_t sl = base.find_last_of("\\/");
        if (sl != std::string::npos) base = base.substr(sl + 1);
        if (ends_with(base, ".ini") && (base == "my.ini" || base == "my.cnf" || base == "mysql.ini"))
            push_unique(inis, fp);
        if (ends_with(low, ".log") && low.find("slow") != std::string::npos)
            push_unique(slogs, fp);
        else if (ends_with(low, ".log") &&
                 (low.find("general") != std::string::npos || base == "mysql.log" ||
                  (low.find("error") == std::string::npos && low.find("ib_") == std::string::npos &&
                   low.find("slow") == std::string::npos && ends_with(base, ".log") &&
                   (base.find("-") == std::string::npos /* hostname.log 常为 general */)))) {
            if (low.find("error") == std::string::npos && low.find("ib_") == std::string::npos &&
                low.find("slow") == std::string::npos)
                push_unique(glogs, fp);
        }
        if (base.find("mysql-bin.") == 0 || base.find("binlog.") == 0 ||
            base.find("-bin.0") != std::string::npos ||
            (ends_with(base, ".index") && (base.find("bin") != std::string::npos)))
            push_unique(blogs, fp);
    };

    auto parse_ini_paths = [&](const std::string& ini, const std::string& def_data) {
        ReadResult r = read_text_file(ini, 512 * 1024);
        if (!r.ok) return;
        std::string datadir = def_data;
        for_each_line(r.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#' || t[0] == ';') return;
            size_t eq = t.find_first_of(" \t=");
            if (eq == std::string::npos) return;
            std::string k = to_lower(trim(t.substr(0, eq)));
            std::string v = trim(t.substr(eq + 1));
            while (!v.empty() && (v.front() == '=' || v.front() == ' ')) v.erase(v.begin());
            if (v.size() >= 2 && ((v.front() == '"' && v.back() == '"') ||
                                  (v.front() == '\'' && v.back() == '\'')))
                v = v.substr(1, v.size() - 2);
            for (char& c : v) if (c == '/') c = '\\';
            auto loc = [&](std::string p) {
                if (p.empty()) return p;
                if (p.size() >= 2 && p[1] == ':') return p;
                if (!datadir.empty()) {
                    char last = datadir.back();
                    return datadir + ((last == '\\' || last == '/') ? "" : "\\") + p;
                }
                return p;
            };
            if ((k == "datadir" || k == "data-dir") && !v.empty()) datadir = loc(v);
            if ((k == "general_log_file" || k == "general-log-file") && !v.empty())
                push_unique(glogs, loc(v));
            if ((k == "slow_query_log_file" || k == "slow-query-log-file" ||
                 k == "slow_query_log" || k == "log_slow_queries") &&
                !v.empty() && v != "1" && v != "ON" && v != "on" && v != "0" && v != "OFF" && v != "off")
                push_unique(slogs, loc(v));
            if ((k == "log_bin" || k == "log-bin" || k == "log_bin_basename") &&
                !v.empty() && v != "1" && v != "ON" && v != "on") {
                std::string b = loc(v);
                push_unique(blogs, b + ".index");
                push_unique(blogs, b + ".000001");
                push_unique(blogs, b);
            }
        });
        // datadir 下常见文件名
        if (dir_exists(datadir)) {
            for (const auto& f : list_entries(datadir, false)) classify_file(f);
        }
    };

    for (const auto& c : cands) {
        // 目录本身的 my.ini / data / logs
        for (const auto& f : list_entries(c, false)) classify_file(f);
        std::string ini = c + "\\my.ini";
        std::string cnf = c + "\\my.cnf";
        std::string data = c + "\\data";
        if (file_exists(ini)) parse_ini_paths(ini, dir_exists(data) ? data : c);
        else if (file_exists(cnf)) parse_ini_paths(cnf, dir_exists(data) ? data : c);
        else if (dir_exists(data)) {
            for (const auto& f : list_entries(data, false)) classify_file(f);
        }
        // phpstudy 有时把 slow 放在实例根而不是 data
        for (const char* n : {"mysql-slow.log", "slow.log", "slow-query.log",
                              "mysql.log", "general.log", "mysql-bin.000001", "binlog.000001"})
            classify_file(c + "\\" + n);
    }

    auto scan_logs = [&](const std::vector<std::string>& files, const char* rule,
                         const char* label, int cap) {
        int scanned = 0, hits = 0;
        std::set<std::string> seen;
        for (const auto& gl : files) {
            if (scanned >= cap) break;
            std::string key = to_lower(gl);
            if (!seen.insert(key).second) continue;
            if (!file_exists(gl)) continue;
            ReadResult r = read_text_file(gl, 16 * 1024 * 1024);
            if (!r.ok) continue;
            ++scanned;
            ctx.planned_source(gl);
            for_each_line(r.content, [&](int, const std::string& line) {
                std::string why;
                if (!::ctfir::mysql_log_suspicious(line, &why)) return;
                ++hits;
                if (hits <= 4) {
                    Finding f;
                    f.rule_id = rule;
                    f.severity = "high";
                    f.confidence = "medium";
                    f.rationale = std::string("MySQL ") + label + " 中发现 " + why + ": " +
                                  line.substr(0, 180) + "（写马/UDF/读文件痕迹——取证金矿）";
                    f.object_ref = gl;
                    f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                    ctx.add_finding(f);
                }
            });
            ctx.checked_source(gl);
        }
        if (scanned > 0)
            ctx.checked_source(std::string("MySQL ") + label + " 内容取证（" +
                               std::to_string(scanned) + " 文件）");
        return scanned;
    };

    scan_logs(glogs, "MID.MYSQL.LOGSHELL.001", "general_log", 6);
    scan_logs(slogs, "MID.MYSQL.SLOWLOG.001", "slow log", 6);
    int bscan = scan_logs(blogs, "MID.MYSQL.BINLOG.001", "binlog", 6);
    if (bscan == 0) {
        for (const auto& b : blogs) {
            if (file_exists(b)) {
                ctx.note("发现 MySQL binlog/index: " + b +
                         "（ROW 格式需 mysqlbinlog 人工还原，工具只扫描 STATEMENT 明文）");
                ctx.checked_source(b);
                break;
            }
        }
    }
    if (glogs.empty() && slogs.empty() && blogs.empty())
        ctx.note("未发现常见 Windows MySQL 日志路径（phpstudy/wamp/xampp/官方）");
    ctx.set_status(ModuleStatus::PASS);
}


} // namespace

void register_mods_w4(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"WIN.BASE.PWD", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_password(c); }});
    mods.push_back({"WIN.BASE.ACC", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_accounts(c); }});
    mods.push_back({"WIN.BASE.REG", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_reg(c); }});
    mods.push_back({"WIN.BASE.PORTS", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_ports(c); }});
    mods.push_back({"WIN.BASE.PERSIST", "1.0.0", "windows", [](ModuleCtx& c) { mod_base_persist(c); }});
    mods.push_back({"MID.MYSQL", "1.0.0", "windows", [](ModuleCtx& c) { mod_mysql_win(c); }});
}

} // namespace ctfir::win
