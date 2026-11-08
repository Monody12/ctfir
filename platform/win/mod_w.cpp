// Windows A 级模块：W01 账户 / W02 登录隐藏 / W04 服务 / W05 自启动(+次要持久化点) / W06 hosts / W08 关键文件哈希
#include "win_common.hpp"

#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace ctfir::win {

namespace {

// ---- W01 账户/管理员组（按 SID 定位管理员组，不靠英文名）----
void mod_acc(ModuleCtx& ctx) {
    // 定位内置管理员组 SID S-1-5-32-544 对应名称（本地化安全）
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admin_sid = nullptr;
    std::wstring admin_group;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_sid)) {
        wchar_t name[256]{}, dom[256]{};
        DWORD nlen = 256, dlen = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, admin_sid, name, &nlen, dom, &dlen, &use))
            admin_group = name;
        FreeSid(admin_sid);
    }
    ctx.note(std::string("管理员组定位(按SID S-1-5-32-544): ") +
             (admin_group.empty() ? "失败" : wide_to_utf8(admin_group).c_str()));

    // 枚举本地用户（level 3: name/RID/flags）
    LPUSER_INFO_3 buf = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS st = NetUserEnum(nullptr, 3, FILTER_NORMAL_ACCOUNT,
                                    (LPBYTE*)&buf, MAX_PREFERRED_LENGTH,
                                    &read, &total, &resume);
    if (st == NERR_Success || st == ERROR_MORE_DATA) {
        std::string userlist;
        for (DWORD i = 0; i < read; ++i) {
            USER_INFO_3& u = buf[i];
            std::string name = wide_to_utf8(u.usri3_name);
            userlist += name + "(RID" + std::to_string(u.usri3_user_id) +
                        (u.usri3_flags & UF_ACCOUNTDISABLE ? ",disabled" : "") + ") ";
        }
        Evidence e;
        e.source_kind = "api";
        e.source_path = "NetUserEnum(level3)";
        e.payload = userlist;
        ctx.add_evidence(e);
        ctx.checked_source("NetUserEnum");
        // $ 结尾账户已包含在枚举中（API 级可见，区别于 net user 显示）——单独提示
        for (DWORD i = 0; i < read; ++i) {
            std::string name = wide_to_utf8(buf[i].usri3_name);
            if (name.size() > 1 && name.back() == '$' && name.find("SUPPORT_") != 0) {
                Finding f;
                f.rule_id = "WIN.ACC.DOLLAR.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "存在以 $ 结尾的账户（部分显示工具不可见，API 可见）: " + name +
                              "（机器账户/服务账户可能合法，需核对 RID 与描述）";
                f.object_ref = "NetUserEnum:" + name;
                f.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(f);
            }
        }
        NetApiBufferFree(buf);
    } else {
        ctx.omitted_source("NetUserEnum", last_error_str("NetUserEnum"));
    }

    // 管理员组成员（SID 路径）
    if (!admin_group.empty()) {
        LOCALGROUP_MEMBERS_INFO_2* mb = nullptr;
        DWORD mread = 0, mtotal = 0;
        DWORD_PTR mresume = 0;
        NET_API_STATUS mst = NetLocalGroupGetMembers(nullptr, admin_group.c_str(), 2,
                                                     (LPBYTE*)&mb, MAX_PREFERRED_LENGTH,
                                                     &mread, &mtotal, &mresume);
        if (mst == NERR_Success) {
            std::string members;
            for (DWORD i = 0; i < mread; ++i) {
                PSID sid = mb[i].lgrmi2_sid;
                LPWSTR sidstr = nullptr;
                std::string sidtxt;
                if (ConvertSidToStringSidW(sid, &sidstr)) {
                    sidtxt = wide_to_utf8(sidstr);
                    LocalFree(sidstr);
                }
                std::string mname = wide_to_utf8(mb[i].lgrmi2_domainandname);
                members += mname + "[" + sidtxt + "] ";
                // 自建账户（RID>1000 的用户 SID）进管理员组 → 重点提示
                PUCHAR cnt = GetSidSubAuthorityCount(sid);
                if (cnt && *cnt >= 1) {
                    DWORD rid = *GetSidSubAuthority(sid, *cnt - 1);
                    if (rid > 1000 && mb[i].lgrmi2_sidusage == SidTypeUser) {
                        Finding f;
                        f.rule_id = "WIN.ACC.ADMIN.001";
                        f.severity = "medium";
                        f.confidence = "medium";
                        f.rationale = "管理员组含自建账户(RID>1000): " + mname + " [" + sidtxt +
                                      "]——授权运维可合法；结合创建时间/日志核实";
                        f.object_ref = "Administrators:" + mname;
                        f.advice_id = "ADVICE.ACC.REVIEW.001";
                        ctx.add_finding(f);
                    }
                }
            }
            Evidence e;
            e.source_kind = "api";
            e.source_path = "NetLocalGroupGetMembers(Administrators by SID)";
            e.payload = members;
            ctx.add_evidence(e);
            ctx.checked_source("NetLocalGroupGetMembers");
            NetApiBufferFree(mb);
        } else {
            ctx.omitted_source("NetLocalGroupGetMembers", last_error_str("NetLocalGroupGetMembers"));
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- W02 登录界面隐藏 ----
void mod_loginhide(ModuleCtx& ctx) {
    const std::wstring sub =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList";
    HKEY h = open_key(HKEY_LOCAL_MACHINE, sub, false);
    if (!h) {
        // 键不存在 = 无该配置（可完成检查）
        ctx.checked_source("HKLM\\" + wide_to_utf8(sub) + " [not_found]（无隐藏配置）");
        ctx.set_status(ModuleStatus::PASS);
        return;
    }
    auto vals = reg_values(h);
    RegCloseKey(h);
    std::string listing;
    for (const auto& v : vals) {
        listing += v.name + "=" + v.data + "(" + v.type + ") ";
        if (v.type == "REG_DWORD" && v.data != "0" && v.name.find("$") == std::string::npos) {
            Finding f;
            f.rule_id = "WIN.ACC.LOGIN_HIDE.001";
            f.severity = "low";
            f.confidence = "medium";
            f.rationale = "登录界面隐藏账户: " + v.name + "（服务账户隐藏属常见；与 W01 账户清单对照）";
            f.object_ref = "HKLM\\" + wide_to_utf8(sub) + "\\" + v.name;
            f.limitations = {"UI 隐藏 ≠ SAM 隐藏；深层 SAM 专题属 W11(未实现)"};
            f.advice_id = "ADVICE.LOGIN_HIDE.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    Evidence e;
    e.source_kind = "registry";
    e.source_path = "HKLM\\" + wide_to_utf8(sub);
    e.payload = listing.empty() ? "(键存在但无值)" : listing;
    ctx.add_evidence(e);
    ctx.checked_source("HKLM\\" + wide_to_utf8(sub));
    ctx.set_status(ModuleStatus::PASS);
}

// ---- W04 服务 ----
void mod_services(ModuleCtx& ctx) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        ctx.omitted_source("SCM", last_error_str("OpenSCManager"));
        ctx.set_status(ModuleStatus::PERMISSION_DENIED);
        return;
    }
    DWORD need = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &need, &count, &resume, nullptr);
    std::vector<BYTE> buf(need);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), need, &need, &count, &resume, nullptr)) {
        ctx.omitted_source("EnumServicesStatusEx", last_error_str("EnumServicesStatusEx"));
        CloseServiceHandle(scm);
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    auto* svc = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS*>(buf.data());
    std::string summary;
    int flag_reboot = 0;
    for (DWORD i = 0; i < count; ++i) {
        if (ctx.expired()) { ctx.note("预算截断，剩余服务未覆盖"); break; }
        SC_HANDLE h = OpenServiceW(scm, svc[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!h) continue;
        QUERY_SERVICE_CONFIGW* qc = nullptr;
        DWORD qn = 0;
        QueryServiceConfigW(h, nullptr, 0, &qn);
        if (qn > 0 && qn < 1024 * 1024) {
            std::vector<BYTE> qb(qn);
            if (QueryServiceConfigW(h, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(qb.data()), qn, &qn)) {
                qc = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(qb.data());
                std::string name = wide_to_utf8(svc[i].lpServiceName);
                std::string disp = wide_to_utf8(svc[i].lpDisplayName);
                std::string path = wide_to_utf8(qc->lpBinaryPathName);
                std::string acct = wide_to_utf8(qc->lpServiceStartName);
                const char* start =
                    qc->dwStartType == SERVICE_AUTO_START ? "AUTO"
                    : qc->dwStartType == SERVICE_DEMAND_START ? "DEMAND"
                    : qc->dwStartType == SERVICE_DISABLED ? "DISABLED" : "OTHER";
                summary += name + "|" + start + "|" + path.substr(0, 120) + "\n";
                bool bad_path = is_writable_path(path);
                bool quoted_space =
                    path.find('"') == std::string::npos &&
                    path.find(" ") != std::string::npos &&
                    to_lower(path).find("\\windows\\system32") == std::string::npos;
                bool net_token = contains_ci(path, "powershell") || contains_ci(path, "certutil") ||
                                 contains_ci(path, "http") || contains_ci(path, "cmd.exe /c");
                if (bad_path || net_token) {
                    Finding f;
                    f.rule_id = "WIN.SVC.SUSPECT.001";
                    f.severity = net_token ? "high" : "medium";
                    f.confidence = "medium";
                    f.rationale = "服务 ImagePath 可疑（可写目录或网络/下载特征）: " + name + " → " + path;
                    f.object_ref = "Services\\" + name;
                    f.limitations = {"第三方软件服务可能合法"};
                    f.advice_id = "ADVICE.SVC.REVIEW.001";
                    ctx.add_finding(f);
                } else if (quoted_space) {
                    // 经典路径劫持面（未加引号含空格）——本机后门排查线索
                    if (++flag_reboot <= 20) {
                        Finding f;
                        f.rule_id = "WIN.SVC.UNQUOTED.001";
                        f.severity = "low";
                        f.confidence = "medium";
                        f.rationale = "服务路径未加引号且含空格（历史劫持面，需人工判断）: " + name + " → " + path.substr(0, 150);
                        f.object_ref = "Services\\" + name;
                        f.advice_id = "ADVICE.SVC.REVIEW.001";
                        ctx.add_finding(f);
                    }
                }
            }
        }
        CloseServiceHandle(h);
    }
    CloseServiceHandle(scm);
    Evidence e;
    e.source_kind = "api";
    e.source_path = "SCM EnumServicesStatusEx(SERVICE_WIN32)";
    e.payload = summary.empty() ? "(0)" : summary;
    ctx.add_evidence(e);
    ctx.checked_source("SCM 枚举");
    ctx.note("驱动服务仅计数未深查（B 级边界）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- W05 自启动 + 次要持久化点 ----
static void scan_run_key(ModuleCtx& ctx, HKEY root, const std::wstring& sub, bool view32,
                         const std::string& label) {
    HKEY h = open_key(root, sub, view32);
    if (!h) {
        ctx.checked_source(label + " [not_found]");
        return;
    }
    auto vals = reg_values(h);
    RegCloseKey(h);
    std::string listing;
    for (const auto& v : vals) {
        listing += v.name + " = " + v.data + "\n";
        bool net = contains_ci(v.data, "powershell") || contains_ci(v.data, "certutil") ||
                   contains_ci(v.data, "http") || contains_ci(v.data, "mshta") ||
                   contains_ci(v.data, "regsvr32") || contains_ci(v.data, "rundll32");
        if (net) {
            Finding f;
            f.rule_id = "WIN.AUTORUN.SUSPECT.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "自启动项含网络/脚本解释器特征: " + label + "\\" + v.name + " = " + v.data.substr(0, 200);
            f.object_ref = label + "\\" + v.name;
            f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
            ctx.add_finding(f);
        } else if (!v.data.empty() && !is_expected_path(v.data) && is_writable_path(v.data)) {
            Finding f;
            f.rule_id = "WIN.AUTORUN.WRITABLE.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "自启动项指向可写目录: " + label + "\\" + v.name + " = " + v.data.substr(0, 200);
            f.object_ref = label + "\\" + v.name;
            f.limitations = {"调试/运维工具常见，需人工核对"};
            f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    Evidence e;
    e.source_kind = "registry";
    e.source_path = label;
    e.payload = listing.empty() ? "(无值)" : listing;
    ctx.add_evidence(e);
    ctx.checked_source(label);
}

void mod_autorun(ModuleCtx& ctx) {
    const std::wstring cv = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion";
    // Run/RunOnce：HKLM 64 位 + 32 位视图 + HKU 已加载用户
    scan_run_key(ctx, HKEY_LOCAL_MACHINE, cv + L"\\Run", false, "HKLM\\...\\Run(64)");
    scan_run_key(ctx, HKEY_LOCAL_MACHINE, cv + L"\\RunOnce", false, "HKLM\\...\\RunOnce(64)");
    scan_run_key(ctx, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", false, "HKLM\\Wow6432Node\\Run(32视图)");
    scan_run_key(ctx, HKEY_LOCAL_MACHINE, cv + L"\\Run", true, "HKLM\\...\\Run(32显式)");
    // HKU：已加载用户
    HKEY hku = open_key(HKEY_USERS, L"", false);
    if (hku) {
        for (const auto& sid : reg_subkeys(hku)) {
            if (sid.find(L"S-1-") != 0 || sid.find(L"_Classes") != std::wstring::npos) continue;
            scan_run_key(ctx, HKEY_USERS, sid + L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         false, "HKU\\" + wide_to_utf8(sid) + "\\Run");
        }
        RegCloseKey(hku);
    } else {
        ctx.omitted_source("HKEY_USERS", "打开失败");
    }
    // Winlogon: Shell / Userinit / Notify / AppInit_DLLs
    std::string shell, userinit, appinit, appinit32;
    reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", false, shell);
    reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", false, userinit);
    reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", false, appinit);
    reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", false, appinit32);
    Evidence we;
    we.source_kind = "registry";
    we.source_path = "HKLM\\...\\Winlogon + Windows\\AppInit_DLLs";
    we.payload = "Shell=" + shell + "\nUserinit=" + userinit +
                 "\nAppInit_DLLs=" + appinit + "\nAppInit_DLLs(32)=" + appinit32;
    ctx.add_evidence(we);
    ctx.checked_source("Winlogon Shell/Userinit");
    ctx.checked_source("AppInit_DLLs(双视图)");
    for (const std::string* p : {&shell, &userinit}) {
        if (p->empty()) continue;
        if (!is_expected_path(*p) && !contains_ci(*p, "explorer.exe") && !contains_ci(*p, "userinit.exe")) {
            Finding f;
            f.rule_id = "WIN.AUTORUN.WINLOGON.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "Winlogon Shell/Userinit 指向非常规程序: " + *p;
            f.object_ref = "Winlogon";
            f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    if (!appinit.empty() && appinit != "0" && !appinit.empty() && appinit.find("<binary>") == std::string::npos && appinit.size() > 3) {
        Finding f;
        f.rule_id = "WIN.AUTORUN.APPINIT.001";
        f.severity = "medium";
        f.confidence = "medium";
        f.rationale = "AppInit_DLLs 非空: " + appinit + "（可能合法，需核实）";
        f.object_ref = "Windows\\AppInit_DLLs";
        f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
        ctx.add_finding(f);
    }
    // IFEO Debugger
    {
        HKEY ifeo = open_key(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", false);
        if (ifeo) {
            int dbg = 0;
            for (const auto& sk : reg_subkeys(ifeo)) {
                if (dbg > 50) break;
                std::string debugger;
                if (reg_get(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + sk,
                            L"Debugger", false, debugger)) {
                    ++dbg;
                    Finding f;
                    f.rule_id = "WIN.AUTORUN.IFEO.001";
                    f.severity = "high";
                    f.confidence = "medium";
                    f.rationale = "IFEO Debugger 劫持: " + wide_to_utf8(sk) + " → " + debugger +
                                  "（调试工具部署可能合法；sethc/utilman 被劫持属粘滞键后门）";
                    f.object_ref = "IFEO\\" + wide_to_utf8(sk);
                    f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
                    ctx.add_finding(f);
                }
            }
            RegCloseKey(ifeo);
            ctx.checked_source("IFEO Debugger 扫描");
        }
    }
    // LSA Authentication Packages / Notification Packages / Security Providers
    for (const auto& pv : {std::make_pair(L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages"),
                           std::make_pair(L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages"),
                           std::make_pair(L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages")}) {
        HKEY h = open_key(HKEY_LOCAL_MACHINE, pv.first, false);
        if (!h) continue;
        auto vals = reg_values(h);
        RegCloseKey(h);
        for (const auto& v : vals) {
            if (v.name != wide_to_utf8(pv.second)) continue;
            Evidence e;
            e.source_kind = "registry";
            e.source_path = "HKLM\\" + wide_to_utf8(pv.first) + "\\" + v.name;
            e.payload = v.data;
            ctx.add_evidence(e);
            ctx.checked_source("LSA " + v.name);
            if (v.data.find("relogia") != std::string::npos || v.data.find("\\\\") != std::string::npos ||
                contains_ci(v.data, "http")) {
                Finding f;
                f.rule_id = "WIN.AUTORUN.LSA.001";
                f.severity = "high";
                f.confidence = "medium";
                f.rationale = "LSA " + v.name + " 含可疑条目: " + v.data;
                f.object_ref = "LSA\\" + v.name;
                f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    }
    // Print Processors
    {
        HKEY h = open_key(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\PrintProcessors", false);
        if (h) {
            std::string listing;
            for (const auto& sk : reg_subkeys(h)) listing += wide_to_utf8(sk) + " ";
            RegCloseKey(h);
            Evidence e;
            e.source_kind = "registry";
            e.source_path = "HKLM\\...\\Print\\PrintProcessors";
            e.payload = listing;
            ctx.add_evidence(e);
            ctx.checked_source("Print Processors");
        }
    }
    // Startup 文件夹（公共 + 当前用户）
    char path[MAX_PATH]{};
    if (SHGetFolderPathA(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, path) == S_OK) {
        WIN32_FIND_DATAA fd;
        std::string pat = std::string(path) + "\\*";
        HANDLE fh = FindFirstFileA(pat.c_str(), &fd);
        if (fh != INVALID_HANDLE_VALUE) {
            std::string listing;
            do {
                if (fd.cFileName[0] == '.') continue;
                std::string fp = std::string(path) + "\\" + fd.cFileName;
                listing += fd.cFileName + std::string(" ");
            } while (FindNextFileA(fh, &fd));
            FindClose(fh);
            Evidence e;
            e.source_kind = "dir";
            e.source_path = path;
            e.payload = listing.empty() ? "(空)" : listing;
            ctx.add_evidence(e);
            ctx.checked_source("公共 Startup");
        }
    }
    if (SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, path) == S_OK) {
        WIN32_FIND_DATAA fd;
        std::string pat = std::string(path) + "\\*";
        HANDLE fh = FindFirstFileA(pat.c_str(), &fd);
        if (fh != INVALID_HANDLE_VALUE) {
            std::string listing;
            do {
                if (fd.cFileName[0] == '.') continue;
                listing += fd.cFileName + std::string(" ");
            } while (FindNextFileA(fh, &fd));
            FindClose(fh);
            Evidence e;
            e.source_kind = "dir";
            e.source_path = path;
            e.payload = listing.empty() ? "(空)" : listing;
            ctx.add_evidence(e);
            ctx.checked_source("当前用户 Startup");
        }
    }
    ctx.note("未加载用户 hive 不覆盖（PLAN 边界）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- W06 hosts ----
void mod_hosts(ModuleCtx& ctx) {
    std::string p = sysroot() + "\\System32\\drivers\\etc\\hosts";
    ReadResult r = read_file(ctx, p);
    if (!r.ok) {
        if (r.access_status == "denied") { ctx.set_status(ModuleStatus::PERMISSION_DENIED); return; }
        ctx.set_status(ModuleStatus::PASS);
        return;
    }
    for_each_line(r.content, [&](int no, const std::string& line) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') return;
        std::istringstream is(t);
        std::string ip, name;
        if (!(is >> ip)) return;
        while (is >> name) {
            if (name == "localhost") continue;
            if (ip == "127.0.0.1" || ip == "::1") continue;
            Finding f;
            f.rule_id = "WIN.HOSTS.MAP.001";
            f.severity = "low";
            f.confidence = "medium";
            f.rationale = "hosts 非默认映射: " + ip + " -> " + name + "（无基线仅列证据）";
            f.object_ref = p + ":" + std::to_string(no);
            f.advice_id = "ADVICE.HOSTS.REVIEW.001";
            ctx.add_finding(f);
        }
    });
    ctx.set_status(ModuleStatus::PASS);
}

// ---- W08 关键文件哈希（含粘滞键后门核对清单）----
void mod_hashes(ModuleCtx& ctx) {
    std::string sys = sysroot() + "\\System32\\";
    const char* files[] = {"cmd.exe", "tasklist.exe", "sethc.exe", "utilman.exe",
                           "osk.exe", "Magnify.exe", "Narrator.exe", "net.exe",
                           "taskmgr.exe", "attrib.exe", "net1.exe", "at.exe"};
    std::string listing;
    for (const char* fn : files) {
        std::string p = sys + fn;
        if (!file_exists(p)) { continue; }
        ctx.planned_source(p);
        ReadResult r = read_text_file(p, 32 * 1024 * 1024);
        if (!r.ok) { ctx.omitted_source(p, r.access_status); continue; }
        Evidence e;
        e.source_kind = "file";
        e.source_path = p;
        e.sha256 = r.raw_sha256;
        e.payload = "(二进制不落 payload) size=" + std::to_string(r.raw_size);
        ctx.add_evidence(e);
        ctx.checked_source(p);
        listing += std::string(fn) + " sha256=" + r.raw_sha256.substr(0, 16) + "… size=" + std::to_string(r.raw_size) + "\n";
    }
    ctx.note("无内置基线：粘滞键后门(sethc/utilman)需与同版本可信系统比对哈希；签名验证见 KNOWN_LIMITATIONS");
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_w1(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"WIN.ACC", "1.0.0", "windows", [](ModuleCtx& c) { mod_acc(c); }});
    mods.push_back({"WIN.LOGINHIDE", "1.0.0", "windows", [](ModuleCtx& c) { mod_loginhide(c); }});
    mods.push_back({"WIN.SVC", "1.0.0", "windows", [](ModuleCtx& c) { mod_services(c); }});
    mods.push_back({"WIN.AUTORUN", "1.0.0", "windows", [](ModuleCtx& c) { mod_autorun(c); }});
    mods.push_back({"WIN.HOSTS", "1.0.0", "windows", [](ModuleCtx& c) { mod_hosts(c); }});
    mods.push_back({"WIN.HASHES", "1.0.0", "windows", [](ModuleCtx& c) { mod_hashes(c); }});
}

} // namespace ctfir::win
