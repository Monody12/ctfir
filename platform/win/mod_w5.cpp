// Windows Server / AD 域控痕迹与凭据防护（v0.8）
// 文件痕迹（GPP/NTDS 副本/IFM/SYSVOL 脚本/GPO）+ 注册表基线（WDigest/NTLMv1/DSRM/LDAP…）。
// 不查询 LDAP、不解密 cpassword、不解析 ntds.dit 哈希。
#include "win_common.hpp"
#include "core/ad_detect.hpp"

#include <cstdlib>
#include <vector>
#include <lm.h>
#include <winsvc.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

namespace ctfir::win {
namespace {

std::string product_type() {
    std::string v;
    reg_get(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
            L"ProductType", false, v);
    return v;
}

bool service_present(const wchar_t* name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE s = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    bool ok = s != nullptr;
    if (s) CloseServiceHandle(s);
    CloseServiceHandle(scm);
    return ok;
}

DWORD service_start_type(const wchar_t* name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE s = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG);
    DWORD start = 0;
    if (s) {
        DWORD need = 0;
        QueryServiceConfigW(s, nullptr, 0, &need);
        if (need > 0 && need < 16 * 1024) {
            std::vector<BYTE> buf(need);
            auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
            if (QueryServiceConfigW(s, cfg, need, &need))
                start = cfg->dwStartType;
        }
        CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
    return start;
}

bool share_named(const wchar_t* name) {
    LPSHARE_INFO_1 buf = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS st = NetShareEnum(nullptr, 1, (LPBYTE*)&buf, MAX_PREFERRED_LENGTH,
                                     &read, &total, &resume);
    if (st != NERR_Success && st != ERROR_MORE_DATA) return false;
    bool found = false;
    if (buf) {
        for (DWORD i = 0; i < read; ++i) {
            if (_wcsicmp(buf[i].shi1_netname, name) == 0) {
                found = true;
                break;
            }
        }
        NetApiBufferFree(buf);
    }
    return found;
}

bool looks_like_dc() {
    std::string pt = product_type();
    if (to_lower(pt) == "lanmannt") return true;
    if (service_present(L"NTDS")) return true;
    std::string win = sysroot();
    if (file_exists(win + "\\NTDS\\ntds.dit")) return true;
    if (dir_exists(win + "\\SYSVOL")) return true;
    if (dir_exists("C:\\SYSVOL")) return true;
    if (share_named(L"SYSVOL") || share_named(L"NETLOGON")) return true;
    return false;
}

template <typename F>
void walk_files(const std::string& root, int depth, int max_depth, int& nfiles, int max_files, F fn) {
    if (depth > max_depth || nfiles >= max_files) return;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((root + "\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == '.' && fd.cFileName[2] == 0)))
            continue;
        std::string fp = root + "\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk_files(fp, depth + 1, max_depth, nfiles, max_files, fn);
        } else {
            ++nfiles;
            fn(fp);
        }
        if (nfiles >= max_files) break;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void add_file_finding(ModuleCtx& ctx, const char* rule, const std::string& path,
                      const std::string& why, const char* sev = "high",
                      const char* advice = "ADVICE.AD.REVIEW.001") {
    Finding f;
    f.rule_id = rule;
    f.severity = sev;
    f.confidence = "high";
    f.rationale = why;
    f.object_ref = path;
    f.advice_id = advice;
    ctx.add_finding(f);
}

std::string read_ad_text(const std::string& fp) {
    ReadResult r = read_text_file(fp, 2 * 1024 * 1024);
    if (r.ok && !r.content.empty()) return normalize_ad_text(r.content);
    // 路径含空格（Windows NT\SecEdit）时 ifstream 偶发失败，回退 CreateFileA。
    HANDLE h = CreateFileA(fp.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return r.content;
    DWORD sz = GetFileSize(h, nullptr);
    if (sz == INVALID_FILE_SIZE) sz = 0;
    if (sz > 2 * 1024 * 1024) sz = 2 * 1024 * 1024;
    std::string buf(sz, '\0');
    DWORD n = 0;
    BOOL ok = (sz == 0) ? TRUE : ReadFile(h, buf.data(), sz, &n, nullptr);
    CloseHandle(h);
    if (!ok) return r.content;
    buf.resize(n);
    return normalize_ad_text(buf);
}

void scan_ad_file(ModuleCtx& ctx, const std::string& fp, const std::string& win) {
    std::string low = to_lower(fp);
    NtdsClass nc = classify_ntds_path(fp, win);
    if (nc == NtdsClass::Copy) {
        add_file_finding(ctx, "WIN.AD.NTDS.COPY.001", fp,
                         "发现 ntds.dit 副本（非域控活动数据库路径）——可能是 IFM/卷影/手工导出，含全域哈希。"
                         "工具不解析哈希；隔离副本并考虑两次重置 krbtgt");
        return;
    }
    if (nc == NtdsClass::Ifm) {
        add_file_finding(ctx, "WIN.AD.IFM.001", fp,
                         "发现 ntdsutil IFM 目录结构（Active Directory\\ntds.dit）——离线装载/secretsdump 典型产物");
        return;
    }
    if (nc == NtdsClass::Live) {
        ctx.note("发现活动 NTDS 数据库 " + fp + "（域控正常文件，不当作副本告警）");
        return;
    }
    if (looks_like_hive_copy_path(fp)) {
        add_file_finding(ctx, "WIN.AD.HIVE.COPY.001", fp,
                         "发现 SAM/SYSTEM/SECURITY 注册表副本（非 system32\\config）——"
                         "reg save / secretsdump 典型产物。工具不解析哈希；隔离副本");
        return;
    }
    if (looks_like_lsass_dump(fp)) {
        add_file_finding(ctx, "WIN.AD.LSASS.DMP.001", fp,
                         "发现 lsass 内存转储——含登录凭据。隔离删除，不要用 mimikatz 打开");
        return;
    }

    bool under_sysvol = low.find("\\sysvol\\") != std::string::npos ||
                        low.find("\\netlogon\\") != std::string::npos ||
                        low.find("\\policies\\") != std::string::npos;
    if ((ends_with(low, ".xml") || ends_with(low, ".inf") || ends_with(low, ".ini") ||
         is_sysvol_script_name(fp)) &&
        (under_sysvol || ends_with(low, ".xml"))) {
        std::string content = read_ad_text(fp);
        if (content.empty() && !ends_with(low, ".xml") && !ends_with(low, ".inf") &&
            !ends_with(low, ".ini")) {
            // 空脚本仍可能是占位；XML/INF 空则没考点
        }
        if (ends_with(low, ".xml") && xml_has_cpassword(content)) {
            add_file_finding(ctx, "WIN.AD.GPP.CPASSWORD.001", fp,
                             "GPP XML 含非空 cpassword（MS14-025）——口令可用公开 AES 密钥解密。"
                             "工具不落明文；删除该 XML 并轮换被写入的账户口令");
        }
        if (ends_with(low, ".xml") && xml_has_gpp_local_admin(content) &&
            (low.find("groups") != std::string::npos || low.find("\\preferences\\") != std::string::npos)) {
            add_file_finding(ctx, "WIN.AD.GPP.ADMIN.001", fp,
                             "GPP Groups.xml 把账户加入 Administrators——域内本地管理员持久化");
        }
        if (ends_with(low, ".xml") && xml_has_gpo_exec(content) &&
            (low.find("\\preferences\\") != std::string::npos ||
             low.find("scheduledtasks") != std::string::npos)) {
            add_file_finding(ctx, "WIN.AD.GPO.TASK.001", fp,
                             "GPO 首选项计划任务含 Exec/Command——域内立即任务持久化（gpupdate 后全域执行）");
        }
        if (ends_with(low, "registry.xml") && under_sysvol) {
            add_file_finding(ctx, "WIN.AD.GPP.REG.001", fp,
                             "SYSVOL 存在 GPP Registry.xml——可向全域写注册表持久化，人工核对 Value");
        }
        if ((ends_with(low, "files.xml") || ends_with(low, "shortcuts.xml")) && under_sysvol) {
            add_file_finding(ctx, "WIN.AD.GPP.FILE.001", fp,
                             "SYSVOL 存在 GPP Files/Shortcuts.xml——可向全域投放文件或快捷方式");
        }
        if (ends_with(low, "services.xml") && under_sysvol) {
            add_file_finding(ctx, "WIN.AD.GPP.SVC.001", fp,
                             "SYSVOL 存在 GPP Services.xml——可改服务二进制/启动类型（域持久化）");
        }
        if (ends_with(low, "scripts.ini") || ends_with(low, "script.ini") ||
            (ends_with(low, ".ini") && low.find("\\scripts\\") != std::string::npos)) {
            std::string cmd;
            if (scripts_ini_has_cmdline(content, &cmd)) {
                add_file_finding(ctx, "WIN.AD.GPO.SCRIPTINI.001", fp,
                                 std::string("GPO scripts.ini 指定登录/启动脚本: ") + cmd);
            }
        }
        // 不要求文件名精确为 GptTmpl.inf（8.3 短名 GPTTMP~1.INF 也要中）
        if (ends_with(low, ".inf") && under_sysvol) {
            std::string extra;
            if (gptmpl_dangerous_extra(content, &extra) || gptmpl_extra_delegation(content, &extra)) {
                add_file_finding(ctx, "WIN.AD.GPO.DELEG.001", fp,
                                 "GptTmpl.inf 危险特权含非 Administrators: " + extra +
                                 "——委派/Debug/TCB 被扩大");
            }
        }
    }

    if (is_sysvol_script_name(fp) && path_looks_like_sysvol_scripts(fp)) {
        add_file_finding(ctx, "WIN.AD.SYSVOL.SCRIPT.001", fp,
                         "SYSVOL/NETLOGON scripts 下存在脚本/可执行文件——域登录脚本持久化，所有域用户可读");
    }
}

void mod_ad_files(ModuleCtx& ctx) {
    std::string win = sysroot();
    std::string pt = product_type();
    bool dc = looks_like_dc();

    Finding role;
    role.rule_id = "WIN.AD.ROLE.001";
    role.severity = "info";
    role.confidence = "high";
    role.object_ref = "ProductType=" + pt;
    role.advice_id = "ADVICE.AD.REVIEW.001";
    if (to_lower(pt) == "lanmannt" || dc) {
        role.rationale =
            "本机呈现域控特征（ProductType=" + pt +
            (dc ? " 或存在 SYSVOL/NTDS/NTDS 服务" : "") +
            "）。本地 SAM 只含 DC 本机账户；Domain Admins / 域用户不在 NetUserEnum 结果里。"
            "已扫描 SYSVOL/GPP/NTDS 副本与凭据防护注册表；不查询 LDAP、不导出哈希。";
    } else if (to_lower(pt) == "servernt") {
        role.rationale =
            "本机是成员服务器（ProductType=ServerNT）。域账户不在本地 SAM。"
            "已扫描可能落到本机的 SYSVOL 副本、NTDS 导出与 Server 凭据防护项。";
    } else {
        role.rationale =
            "本机是工作站（ProductType=" + (pt.empty() ? "WinNT?" : pt) +
            "）。不能把本地 Administrators 当成 Domain Admins。"
            "若赛题是域控，应在 DC 上跑本工具；本机仍会扫 GPP/NTDS 文件痕迹。";
    }
    ctx.add_finding(role);

    Evidence e;
    e.source_kind = "registry";
    e.source_path = "ProductOptions\\ProductType";
    e.payload = "ProductType=" + pt + " looks_like_dc=" + std::string(dc ? "yes" : "no");
    ctx.add_evidence(e);
    ctx.checked_source("AD 角色");

    std::vector<std::string> roots = {
        win + "\\SYSVOL",
        "C:\\SYSVOL",
        win + "\\NTDS",
        win + "\\Temp",
        "C:\\Temp",
        "C:\\Users\\Public",
        "C:\\ProgramData",
    };
    char up[MAX_PATH]{};
    if (GetEnvironmentVariableA("USERPROFILE", up, MAX_PATH) > 0) {
        roots.push_back(std::string(up) + "\\Desktop");
        roots.push_back(std::string(up) + "\\Documents");
        roots.push_back(std::string(up) + "\\Downloads");
    }
    for (const auto& d : ctx.config().extra_dirs)
        roots.push_back(d);

    int nfiles = 0;
    const int kMaxAd = 2000;
    std::vector<std::string> seen;
    auto scan_once = [&](const std::string& fp) {
        if (!file_exists(fp)) return;
        std::string l = to_lower(fp);
        for (const auto& s : seen)
            if (s == l) return;
        seen.push_back(l);
        scan_ad_file(ctx, fp, win);
    };
    for (const auto& root : roots) {
        if (!dir_exists(root)) continue;
        ctx.planned_source(root);
        int before = nfiles;
        walk_files(root, 0, 12, nfiles, kMaxAd, [&](const std::string& fp) {
            if (!ad_file_candidate(fp)) {
                --nfiles;
                return;
            }
            scan_once(fp);
        });
        ctx.checked_source(root + " [" + std::to_string(nfiles - before) + " candidates]");
        if (nfiles >= kMaxAd) {
            ctx.note("AD 文件扫描达到候选文件上限，未覆盖其余目录");
            break;
        }
        if (ctx.expired()) break;
    }

    const char* probes[] = {
        "\\Temp\\ntds.dit", "\\Temp\\ntds.dit.bak", "\\Temp\\ctfir-marker-ntds.dit",
        "\\Temp\\sam.save", "\\Temp\\system.save", "\\Temp\\security.save",
        "\\Temp\\lsass.dmp", "\\Temp\\lsass.exe.dmp",
        "\\Temp\\ctfir-marker-ifm\\registry\\SYSTEM",
        "\\Temp\\ctfir-marker-ifm\\registry\\SECURITY",
        "\\Temp\\ctfir-marker-ifm\\registry\\SAM",
    };
    for (const char* rel : probes)
        scan_once(win + rel);
    scan_once("C:\\Temp\\ntds.dit");
    scan_once("C:\\Temp\\sam.save");
    scan_once("C:\\Users\\Public\\ntds.dit");
    scan_once("C:\\Users\\Public\\Documents\\ntds.dit");
    scan_once("C:\\Users\\Public\\Desktop\\ntds.dit");
    scan_once("C:\\Users\\Public\\sam.save");
    scan_once("C:\\Users\\Public\\lsass.dmp");

    ctx.set_status(ModuleStatus::PASS);
}

void add_reg_finding(ModuleCtx& ctx, const char* rule, const std::string& obj,
                     const std::string& why, const char* sev = "high") {
    Finding f;
    f.rule_id = rule;
    f.severity = sev;
    f.confidence = "high";
    f.rationale = why;
    f.object_ref = obj;
    f.advice_id = "ADVICE.HARDEN.001";
    ctx.add_finding(f);
}

void mod_ad_reg(ModuleCtx& ctx) {
    bool dc = looks_like_dc();
    std::string v;

    // DSRM：2=任意时刻可用 DSRM 管理员登录（高危）
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"DsrmAdminLogonBehavior", false, v) &&
        (v == "1" || v == "2")) {
        add_reg_finding(ctx, "WIN.AD.DSRM.LOGON.001",
                        "Lsa\\DsrmAdminLogonBehavior",
                        "DSRM 管理员可在 AD 在线时登录（DsrmAdminLogonBehavior=" + v +
                        "）。0=仅修复模式。应改回 0 并轮换 DSRM 口令");
    }
    ctx.checked_source("DsrmAdminLogonBehavior");

    // LDAP 签名：键存在且为 0 才报（工作站默认无此键）
    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                L"LDAPServerIntegrity", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.AD.LDAP.NOSIGN.001",
                        "NTDS\\Parameters\\LDAPServerIntegrity",
                        "LDAP 签名关闭（LDAPServerIntegrity=0）。应设为 2（要求签名）");
    }
    ctx.checked_source("LDAPServerIntegrity");

    // DC 上的打印后台：PrintNightmare / PetitPotam
    if (dc) {
        DWORD st = service_start_type(L"Spooler");
        if (st == SERVICE_AUTO_START || st == SERVICE_DEMAND_START) {
            add_reg_finding(ctx, "WIN.AD.SPOOLER.DC.001",
                            "Service\\Spooler",
                            "域控特征机器上 Print Spooler 仍自动/手动启动（PrintNightmare/强制认证）。"
                            "无打印需求应 sc config Spooler start= disabled",
                            "high");
        }
        v.clear();
        reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                L"RequireSecuritySignature", false, v);
        if (v != "1") {
            add_reg_finding(ctx, "WIN.AD.SMBSIGN.001",
                            "LanmanServer\\Parameters\\RequireSecuritySignature",
                            "域控特征机器未强制 SMB 签名（RequireSecuritySignature=" +
                            (v.empty() ? "缺省" : v) + "）。应设为 1",
                            "medium");
        }
    }
    ctx.checked_source("DC Spooler/SMB 签名");

    // WDigest 明文凭据
    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                L"UseLogonCredential", false, v) &&
        v == "1") {
        add_reg_finding(ctx, "WIN.BASE.WDIGEST.001",
                        "WDigest\\UseLogonCredential",
                        "WDigest UseLogonCredential=1——lsass 保留明文口令，mimikatz 直接读");
    }
    ctx.checked_source("WDigest");

    // NTLMv1
    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"LmCompatibilityLevel", false, v)) {
        int lv = atoi(v.c_str());
        if (lv >= 0 && lv <= 2) {
            add_reg_finding(ctx, "WIN.BASE.NTLMV1.001",
                            "Lsa\\LmCompatibilityLevel",
                            "LmCompatibilityLevel=" + v + " 允许 LM/NTLMv1。基线建议 5（仅 NTLMv2）");
        }
    }
    ctx.checked_source("LmCompatibilityLevel");

    // Pass-the-Hash：LocalAccountTokenFilterPolicy
    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                L"LocalAccountTokenFilterPolicy", false, v) &&
        v == "1") {
        add_reg_finding(ctx, "WIN.BASE.LATFP.001",
                        "Policies\\System\\LocalAccountTokenFilterPolicy",
                        "LocalAccountTokenFilterPolicy=1——本地管理员网络登录给完整令牌，利于 PTH");
    }
    ctx.checked_source("LATFP");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"NoLmHash", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.BASE.NOLMHASH.001",
                        "Lsa\\NoLmHash",
                        "NoLmHash=0——仍存储 LM 哈希。应设为 1");
    }
    ctx.checked_source("NoLmHash");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"RestrictAnonymousSAM", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.BASE.RESTRICTANON.001",
                        "Lsa\\RestrictAnonymousSAM",
                        "RestrictAnonymousSAM=0——允许匿名枚举 SAM 账户。应设为 1",
                        "medium");
    }
    ctx.checked_source("RestrictAnonymousSAM");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"EveryoneIncludesAnonymous", false, v) &&
        v == "1") {
        add_reg_finding(ctx, "WIN.BASE.EVERYONEANON.001",
                        "Lsa\\EveryoneIncludesAnonymous",
                        "EveryoneIncludesAnonymous=1——匿名用户获得 Everyone 权限。应设为 0");
    }
    ctx.checked_source("EveryoneIncludesAnonymous");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                L"EnablePlainTextPassword", false, v) &&
        v == "1") {
        add_reg_finding(ctx, "WIN.BASE.PLAINSMB.001",
                        "LanmanWorkstation\\EnablePlainTextPassword",
                        "允许向第三方 SMB 发送明文口令（EnablePlainTextPassword=1）。应设为 0");
    }
    ctx.checked_source("EnablePlainTextPassword");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint",
                L"NoWarningNoElevationOnInstall", false, v) &&
        v == "1") {
        add_reg_finding(ctx, "WIN.BASE.PNP.ELEV.001",
                        "PointAndPrint\\NoWarningNoElevationOnInstall",
                        "PointAndPrint 安装驱动不警告不提权（PrintNightmare 利用面）。应删除或设 0");
    }
    ctx.checked_source("PointAndPrint");

    v.clear();
    bool aie = false;
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                L"AlwaysInstallElevated", false, v) &&
        v == "1")
        aie = true;
    std::string v2;
    if (reg_get(HKEY_CURRENT_USER,
                L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                L"AlwaysInstallElevated", false, v2) &&
        v2 == "1")
        aie = true;
    if (aie) {
        add_reg_finding(ctx, "WIN.BASE.ALWAYSINST.001",
                        "Installer\\AlwaysInstallElevated",
                        "AlwaysInstallElevated=1——普通用户可用 MSI 系统权限安装。HKLM 与 HKCU 都应回 0");
    }
    ctx.checked_source("AlwaysInstallElevated");

    v.clear();
    bool winrm_bad = false;
    std::string why;
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
                L"AllowUnencrypted", false, v) &&
        v == "1") {
        winrm_bad = true;
        why = "AllowUnencrypted=1";
    }
    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
                L"AllowBasic", false, v) &&
        v == "1") {
        winrm_bad = true;
        if (!why.empty()) why += " 且 ";
        why += "AllowBasic=1";
    }
    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
                L"AllowUnencrypted", false, v) &&
        v == "1") {
        winrm_bad = true;
        if (!why.empty()) why += " 且 ";
        why += "Client.AllowUnencrypted=1";
    }
    if (winrm_bad) {
        add_reg_finding(ctx, "WIN.BASE.WINRM.UNENC.001",
                        "WinRM\\Service",
                        "WinRM " + why + "——远程管理走明文/Basic。应关闭或强制 HTTPS");
    }
    ctx.checked_source("WinRM");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                L"DisablePasswordChange", false, v) &&
        v == "1") {
        add_reg_finding(ctx, "WIN.AD.MACHPWD.001",
                        "Netlogon\\DisablePasswordChange",
                        "计算机账户密码不再自动更换（DisablePasswordChange=1）——域机器账户可被长期滥用");
    }
    ctx.checked_source("DisablePasswordChange");

    v.clear();
    std::string seal_why;
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                L"SealSecureChannel", false, v) &&
        v == "0")
        seal_why = "SealSecureChannel=0";
    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                L"RequireSignOrSeal", false, v) &&
        v == "0") {
        if (!seal_why.empty()) seal_why += " 且 ";
        seal_why += "RequireSignOrSeal=0";
    }
    if (!seal_why.empty()) {
        add_reg_finding(ctx, "WIN.BASE.SEALCHAN.001",
                        "Netlogon\\secure channel",
                        "安全通道未加密/未签名（" + seal_why + "）。两键均应回 1");
    }
    ctx.checked_source("SealSecureChannel");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LDAP",
                L"LDAPClientIntegrity", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.BASE.LDAPCLIENT.001",
                        "LDAP\\LDAPClientIntegrity",
                        "LDAP 客户端签名关闭（LDAPClientIntegrity=0）。应设为 1 或 2");
    }
    ctx.checked_source("LDAPClientIntegrity");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                L"LdapEnforceChannelBinding", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.AD.LDAP.BIND.001",
                        "NTDS\\LdapEnforceChannelBinding",
                        "LDAP 通道绑定显式关闭（LdapEnforceChannelBinding=0）。应设为 2（Always）");
    }
    ctx.checked_source("LdapEnforceChannelBinding");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                L"ConsentPromptBehaviorAdmin", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.BASE.UAC.NOPROMPT.001",
                        "Policies\\System\\ConsentPromptBehaviorAdmin",
                        "UAC 对管理员不提示直接提权（ConsentPromptBehaviorAdmin=0）");
    }
    ctx.checked_source("ConsentPromptBehaviorAdmin");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                L"DisableCAD", false, v) &&
        v == "1") {
        add_reg_finding(ctx, "WIN.BASE.DISABLECAD.001",
                        "Policies\\System\\DisableCAD",
                        "关闭 Ctrl+Alt+Del 安全登录注意（DisableCAD=1）");
    }
    ctx.checked_source("DisableCAD");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint",
                L"RestrictDriverInstallationToAdministrators", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.BASE.PNP.ADMIN.001",
                        "PointAndPrint\\RestrictDriverInstallationToAdministrators",
                        "非管理员可装打印驱动（RestrictDriverInstallationToAdministrators=0，PrintNightmare）");
    }
    ctx.checked_source("RestrictDriverInstallationToAdministrators");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                L"SecurityLayer", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.BASE.RDP.SECLAYER.001",
                        "RDP-Tcp\\SecurityLayer",
                        "RDP 安全层为 RDP（SecurityLayer=0）——无 TLS，易中间人。应设 1 或 2");
    }
    ctx.checked_source("RDP SecurityLayer");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                L"CachedLogonsCount", false, v)) {
        int n = atoi(v.c_str());
        if (n >= 50) {
            add_reg_finding(ctx, "WIN.BASE.CACHEDLOGON.001",
                            "Winlogon\\CachedLogonsCount",
                            "缓存域登录数过大（CachedLogonsCount=" + v +
                            "）。过大便于离线破解缓存哈希；常见基线 ≤10",
                            "medium");
        }
    }
    ctx.checked_source("CachedLogonsCount");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                L"enableforcedlogoff", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.BASE.FORCELOGOFF.001",
                        "LanmanServer\\enableforcedlogoff",
                        "超过登录时间不强制注销（enableforcedlogoff=0）。技能赛常要求开启");
    }
    ctx.checked_source("enableforcedlogoff");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                L"NtlmMinClientSec", false, v) &&
        v == "0") {
        add_reg_finding(ctx, "WIN.BASE.NTLMSEC.001",
                        "MSV1_0\\NtlmMinClientSec",
                        "NTLM 会话安全为 0（无 128 位/NTLMv2 session）。应至少 0x20080000");
    }
    ctx.checked_source("NtlmMinClientSec");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell",
                L"ExecutionPolicy", false, v)) {
        std::string lv = to_lower(v);
        if (lv.find("unrestricted") != std::string::npos || lv.find("bypass") != std::string::npos) {
            add_reg_finding(ctx, "WIN.BASE.PS.UNRESTRICT.001",
                            "PowerShell\\ExecutionPolicy",
                            "计算机策略 PowerShell ExecutionPolicy=" + v +
                            "——任意脚本可执行。应 Restricted/RemoteSigned/AllSigned");
        }
    }
    ctx.checked_source("PowerShell ExecutionPolicy");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                L"MinEncryptionLevel", false, v)) {
        int n = atoi(v.c_str());
        if (n >= 0 && n <= 1) {
            add_reg_finding(ctx, "WIN.BASE.RDP.ENCRYPT.001",
                            "RDP-Tcp\\MinEncryptionLevel",
                            "RDP 加密级别过低（MinEncryptionLevel=" + v +
                            "，Low/Client Compatible 以下）。技能赛常要求 High=3");
        }
    }
    ctx.checked_source("RDP MinEncryptionLevel");

    {
        DWORD st = service_start_type(L"RemoteRegistry");
        if (st == SERVICE_AUTO_START) {
            add_reg_finding(ctx, "WIN.BASE.REMOTEREG.001",
                            "Service\\RemoteRegistry",
                            "Remote Registry 自动启动——远程可读 SAM/SECURITY。应 sc config start= disabled",
                            "medium");
        }
    }
    ctx.checked_source("RemoteRegistry");

    v.clear();
    if (reg_get(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"ForceGuest", false, v) &&
        v == "1") {
        add_reg_finding(ctx, "WIN.BASE.FORCEGUEST.001",
                        "Lsa\\ForceGuest",
                        "网络访问按来宾（ForceGuest=1）。应设 0（经典 - 对本地用户验证）");
    }
    ctx.checked_source("ForceGuest");

    // 防火墙三配置文件
    struct FwP { const wchar_t* sub; const char* name; };
    FwP fwp[] = {
        {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile", "Domain"},
        {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", "Standard"},
        {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile", "Public"},
    };
    std::string off;
    for (const auto& p : fwp) {
        v.clear();
        if (reg_get(HKEY_LOCAL_MACHINE, p.sub, L"EnableFirewall", false, v) && v == "0") {
            if (!off.empty()) off += ",";
            off += p.name;
        }
    }
    if (!off.empty()) {
        add_reg_finding(ctx, "WIN.BASE.FW.OFF.001",
                        "FirewallPolicy\\" + off,
                        "Windows 防火墙配置文件已关闭: " + off +
                        "。赛题常要求三配置文件均启用；先放行 SSH/RDP/业务端口再开",
                        "medium");
    }
    ctx.checked_source("Firewall profiles");

    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_w5(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"WIN.AD.FILES", "1.0.0", "windows", [](ModuleCtx& c) { mod_ad_files(c); }});
    mods.push_back({"WIN.AD.REG", "1.0.0", "windows", [](ModuleCtx& c) { mod_ad_reg(c); }});
}

} // namespace ctfir::win
