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
        // 账户事实化（A7C9-W01）：全量清单 + 非内置账户逐个呈现
        {
            std::string inv;
            for (DWORD i = 0; i < read; ++i) {
                USER_INFO_3& u = buf[i];
                inv += wide_to_utf8(u.usri3_name) + "(RID" + std::to_string(u.usri3_user_id) +
                       (u.usri3_flags & UF_ACCOUNTDISABLE ? ",禁用" : ",活动") + ") ";
            }
            Finding fsum;
            fsum.rule_id = "WIN.ACC.INVENTORY.001";
            fsum.severity = "info";
            fsum.confidence = "high";
            fsum.rationale = "本地账户清单（事实呈现）: " + inv + "——不构成恶意判定，供与隐藏键/管理员组交叉核实";
            fsum.object_ref = "NetUserEnum";
            fsum.advice_id = "ADVICE.ACC.REVIEW.001";
            ctx.add_finding(fsum);
            for (DWORD i = 0; i < read; ++i) {
                USER_INFO_3& u = buf[i];
                if (u.usri3_user_id <= 1000) continue; // 内置段(500 Administrator/501 Guest 等)
                Finding f;
                f.rule_id = "WIN.ACC.CUSTOM.001";
                f.severity = "low";
                f.confidence = "high";
                f.rationale = "非内置本地账户: " + wide_to_utf8(u.usri3_name) +
                              " (RID " + std::to_string(u.usri3_user_id) +
                              (u.usri3_flags & UF_ACCOUNTDISABLE ? "，已禁用" : "，活动") +
                              ")——授权运维/自建服务账户常见，需核实创建来源";
                f.object_ref = "NetUserEnum:" + wide_to_utf8(u.usri3_name);
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
                    // Guest/克隆账号进管理员组（知攻善防·Where-1S-tHe-Hacker：Guest 被加管理员组）
                    if (mb[i].lgrmi2_sidusage == SidTypeUser && rid == 501) {
                        Finding f;
                        f.rule_id = "WIN.ACC.GUESTADMIN.001";
                        f.severity = "high";
                        f.confidence = "high";
                        f.rationale = "Guest 账户在管理员组内: " + mname +
                                      " [" + sidtxt + "]——克隆账号/提权痕迹（Guest 默认不属管理员组）";
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
        // 语义（A7C9-W02 回归）：UserList DWORD **0 = 登录界面隐藏**，1 = 显式显示
        if (v.type == "REG_DWORD" && v.data == "0") {
            Finding f;
            f.rule_id = "WIN.ACC.LOGIN_HIDE.001";
            f.severity = "low";
            f.confidence = "high";
            f.rationale = "登录界面隐藏账户: " + v.name + "（UserList=0）；服务账户隐藏属常见，"
                          "需与账户清单/禁用状态/管理员组关联判断";
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
        } else {
            // 引用路径分析（A7C9-W03 回归）：cmd /c ""C:\CTF-Test\harmless.cmd"" 类形态——
            // 主路径在 System32 但参数里引用了外部脚本
            for (const auto& rp : extract_paths(v.data)) {
                if (is_expected_path(rp)) continue;
                Finding f;
                f.rule_id = "WIN.AUTORUN.REFPATH.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "自启动引用非常规路径: " + rp.substr(0, 150) +
                              "（值名 " + v.name + "）——需人工核对被引用脚本/程序内容";
                f.object_ref = label + "\\" + v.name;
                f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
                ctx.add_finding(f);
                break; // 每值一条防刷屏
            }
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
    // 登录脚本持久化点（T1037）与 Boot Execute
    {
        std::string logonscript, bootexec;
        reg_get(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                L"UserInitMprLogonScript", false, logonscript);
        reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                L"BootExecute", false, bootexec);
        Evidence le;
        le.source_kind = "registry";
        le.source_path = "Winlogon\\UserInitMprLogonScript + SessionManager\\BootExecute";
        le.payload = "UserInitMprLogonScript=" + logonscript + "\nBootExecute=" + bootexec;
        ctx.add_evidence(le);
        ctx.checked_source("UserInitMprLogonScript/BootExecute");
        if (!logonscript.empty()) {
            Finding f;
            f.rule_id = "WIN.AUTORUN.LOGONSCRIPT.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "Winlogon UserInitMprLogonScript 登录脚本持久化: " + logonscript.substr(0, 200);
            f.object_ref = "Winlogon\\UserInitMprLogonScript";
            f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
            ctx.add_finding(f);
        }
        // MULTI_SZ 由 reg_get 以顿号拼接。默认唯一项为 "autocheck autochk *"；
        // 附加条目（即便保留 autocheck）也报——这才是真实的启动劫持形态。
        auto is_default_boot = [](std::string e) {
            while (!e.empty() && (e.back() == '\0' || e.back() == ' ' || e.back() == '\r' || e.back() == '\n'))
                e.pop_back();
            size_t a = e.find_first_not_of(" \t");
            if (a == std::string::npos) return true;
            std::string t = to_lower(e.substr(a));
            return t == "autocheck autochk *" || t == "autocheck autochk*";
        };
        bool unexpected_boot = false;
        if (!bootexec.empty() && bootexec != "<binary>") {
            const std::string delim = "、";
            size_t pos = 0;
            for (;;) {
                size_t n = bootexec.find(delim, pos);
                std::string part = (n == std::string::npos) ? bootexec.substr(pos)
                                                            : bootexec.substr(pos, n - pos);
                if (!part.empty() && !is_default_boot(part)) unexpected_boot = true;
                if (n == std::string::npos) break;
                pos = n + delim.size();
            }
        }
        if (unexpected_boot) {
            Finding f;
            f.rule_id = "WIN.AUTORUN.BOOTEXECUTE.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "BootExecute 非默认值（默认 autocheck autochk *）: " + bootexec.substr(0, 200);
            f.object_ref = "SessionManager\\BootExecute";
            f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
            ctx.add_finding(f);
        }
    }
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
    // Startup 文件夹（公共 + 当前用户）：列清单，脚本/可执行另出 finding（W10 考点）
    auto scan_startup = [&](int csidl, const char* label) {
        char path[MAX_PATH]{};
        if (SHGetFolderPathA(nullptr, csidl, nullptr, 0, path) != S_OK) return;
        WIN32_FIND_DATAA fd;
        std::string pat = std::string(path) + "\\*";
        HANDLE fh = FindFirstFileA(pat.c_str(), &fd);
        if (fh == INVALID_HANDLE_VALUE) return;
        std::string listing;
        do {
            if (fd.cFileName[0] == '.') continue;
            std::string name = fd.cFileName;
            listing += name + " ";
            std::string low = to_lower(name);
            if (low == "desktop.ini" || ends_with(low, ".lnk")) continue;
            bool sus = ends_with(low, ".vbs") || ends_with(low, ".vbe") ||
                       ends_with(low, ".bat") || ends_with(low, ".cmd") ||
                       ends_with(low, ".js") || ends_with(low, ".jse") ||
                       ends_with(low, ".wsf") || ends_with(low, ".wsh") ||
                       ends_with(low, ".ps1") || ends_with(low, ".exe") ||
                       ends_with(low, ".scr") || ends_with(low, ".com");
            if (!sus) continue;
            Finding f;
            f.rule_id = "WIN.AUTORUN.SUSPECT.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = std::string("Startup 启动文件夹含脚本/可执行: ") + path + "\\" + name;
            f.object_ref = std::string(path) + "\\" + name;
            f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
            ctx.add_finding(f);
        } while (FindNextFileA(fh, &fd));
        FindClose(fh);
        Evidence e;
        e.source_kind = "dir";
        e.source_path = path;
        e.payload = listing.empty() ? "(空)" : listing;
        ctx.add_evidence(e);
        ctx.checked_source(label);
    };
    scan_startup(CSIDL_COMMON_STARTUP, "公共 Startup");
    scan_startup(CSIDL_STARTUP, "当前用户 Startup");
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
    int zero_sink = 0;  // 0.0.0.0 沉坑计数（屏蔽列表惯例；聚合避免刷屏）
    for_each_line(r.content, [&](int no, const std::string& line0) {
        std::string line = line0;
        size_t hash = line.find('#');            // 行内注释剥离（A7C9-W05 变体）
        if (hash != std::string::npos) line = line.substr(0, hash);
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') return;
        std::istringstream is(t);
        std::string ip, name;
        if (!(is >> ip)) return;
        bool loopback = (ip == "127.0.0.1" || ip == "::1" || starts_with(ip, "127."));
        if (ip == "0.0.0.0") {
            // 沉坑屏蔽：聚合计数，不逐条报
            for (std::string nm; is >> nm;) {
                if (!starts_with(nm, "localhost") && !starts_with(nm, "ip6-")) ++zero_sink;
            }
            return;
        }
        while (is >> name) {
            if (starts_with(name, "localhost") || starts_with(name, "ip6-")) continue;
            if (loopback) {
                // A7C9-W05 回归：127.0.0.1 绑定非常规名仍是值得核实的线索
                Finding f;
                f.rule_id = "WIN.HOSTS.LOOPBACK.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "本机回环绑定非常规名: " + ip + " -> " + name +
                              "（本地测试/屏蔽常见；陌生域名需核实）";
                f.object_ref = p + ":" + std::to_string(no);
                f.advice_id = "ADVICE.HOSTS.REVIEW.001";
                ctx.add_finding(f);
            } else {
                Finding f;
                f.rule_id = "WIN.HOSTS.MAP.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "hosts 非默认映射: " + ip + " -> " + name + "（无基线仅列证据）";
                f.object_ref = p + ":" + std::to_string(no);
                f.advice_id = "ADVICE.HOSTS.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    });
    if (zero_sink > 0)
        ctx.note("hosts 含 " + std::to_string(zero_sink) + " 条 0.0.0.0 沉坑（屏蔽列表惯例；如需逐条人工核对）");
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
