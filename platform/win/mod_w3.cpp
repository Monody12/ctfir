// Windows 痕迹模块族（v0.3 Phase1）：Prefetch / ShimCache(启发式) / USBSTOR / RDP-MRU /
// 防火墙规则 / 共享 / 驱动服务可写路径
#include "win_common.hpp"

#include <netfw.h>
#include <lm.h>
#include <map>
#include <set>

#pragma comment(lib, "netapi32.lib")

namespace ctfir::win {

namespace {

// ---- WIN.PREFETCH：预取文件枚举（文件名即程序名）----
void mod_prefetch(ModuleCtx& ctx) {
    std::string dir = sysroot() + "\\Prefetch";
    ctx.planned_source(dir);
    WIN32_FIND_DATAA fd;
    HANDLE fh = FindFirstFileA((dir + "\\*.pf").c_str(), &fd);
    if (fh == INVALID_HANDLE_VALUE) {
        // 区分不存在（SuperFetch 未启用/清空）与拒绝
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            ctx.omitted_source(dir, "PERMISSION_DENIED（Prefetch 需管理员读取）");
            ctx.set_status(ModuleStatus::PERMISSION_DENIED);
            return;
        }
        ctx.checked_source(dir + " [not_found]（无预取文件）");
        ctx.note("Prefetch 为空：可能是被清理/禁用——本身是取证线索");
        ctx.set_status(ModuleStatus::PASS);
        return;
    }
    std::string listing;
    int cnt = 0;
    do {
        if (++cnt > 1500) { ctx.note("超 1500 截断"); break; }
        std::string fn = fd.cFileName;                       // NAME-HASH.pf
        std::string prog = fn.substr(0, fn.rfind('-'));      // 去哈希
        FILETIME ft = fd.ftLastWriteTime;
        FILETIME lt{};
        FileTimeToLocalFileTime(&ft, &lt);
        SYSTEMTIME st{};
        FileTimeToSystemTime(&lt, &st);
        char tbuf[24];
        std::snprintf(tbuf, sizeof(tbuf), "%04u-%02u-%02u %02u:%02u",
                      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        listing += tbuf + std::string("  ") + prog + "\n";
        std::string low = to_lower(prog);
        if (contains_ci(low, "kdevtmpfsi") || contains_ci(low, "kinsing") ||
            contains_ci(low, "xmrig") || contains_ci(low, "miner") ||
            contains_ci(low, "mimikatz") || contains_ci(low, "nc ") || low == "nc") {
            Finding f;
            f.rule_id = "WIN.TRACE.PREFETCH.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "Prefetch 记录执行过可疑程序: " + prog + "（最近执行 " + tbuf + "）";
            f.object_ref = dir + "\\" + fn;
            f.advice_id = "ADVICE.MINER.REVIEW.001";
            ctx.add_finding(f);
        }
    } while (FindNextFileA(fh, &fd));
    FindClose(fh);
    Evidence e;
    e.source_kind = "dir";
    e.source_path = dir;
    e.payload = "count=" + std::to_string(cnt) + "\n" + listing.substr(0, 64 * 1024);
    ctx.add_evidence(e);
    ctx.checked_source(dir);
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.SHIMCACHE：AppCompatCache 启发式路径提取 ----
void mod_shimcache(ModuleCtx& ctx) {
    std::string data;
    if (!reg_get(HKEY_LOCAL_MACHINE,
                 L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                 L"AppCompatCache", false, data)) {
        ctx.checked_source("AppCompatCache [not_found]");
        ctx.set_status(ModuleStatus::PASS);
        return;
    }
    // 启发式提取：blob 中定位 UTF-16LE 的疑似执行路径（含 \ 或 :\/ 且含 . 扩展名）。
    // 不依赖具体 Win7 结构版本（失败不影响其他证据）；解析属启发式，如实标注。
    ctx.planned_source("AppCompatCache");
    std::vector<std::string> paths;
    std::string raw;
    {
        // reg_get 给的是字符串化——二进制会变 <binary NB>；改为原生读字节
        HKEY h = open_key(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", false);
        if (h) {
            DWORD type = 0, size = 0;
            if (RegQueryValueExW(h, L"AppCompatCache", nullptr, &type, nullptr, &size) == ERROR_SUCCESS &&
                size > 4 && size < 4 * 1024 * 1024 && type == REG_BINARY) {
                std::vector<BYTE> buf(size);
                if (RegQueryValueExW(h, L"AppCompatCache", nullptr, &type, buf.data(), &size) == ERROR_SUCCESS)
                    raw.assign(reinterpret_cast<char*>(buf.data()), size);
            }
            RegCloseKey(h);
        }
    }
    if (raw.empty()) {
        ctx.omitted_source("AppCompatCache", "二进制不可读/为空");
        ctx.set_status(ModuleStatus::PASS);
        return;
    }
    // UTF-16LE 路径扫描
    size_t n = raw.size();
    for (size_t i = 0; i + 2 < n; i += 2) {
        // 找一个可打印 ASCII 的 UTF-16LE 序列起点（含 \Device\ 或 X:\ 形态）
        wchar_t w0 = static_cast<wchar_t>(static_cast<unsigned char>(raw[i])) |
                     (static_cast<wchar_t>(static_cast<unsigned char>(raw[i + 1])) << 8);
        bool pathish = (w0 == L'\\') ||
                       ((w0 >= L'A' && w0 <= L'Z') &&
                        i + 3 < n &&
                        static_cast<unsigned char>(raw[i + 2]) == ':');
        if (!pathish) continue;
        std::wstring w;
        size_t j = i;
        while (j + 1 < n) {
            wchar_t wc = static_cast<wchar_t>(static_cast<unsigned char>(raw[j])) |
                         (static_cast<wchar_t>(static_cast<unsigned char>(raw[j + 1])) << 8);
            if (wc == 0 || wc > 0x7E || wc == L'\n' || wc == L'\r') break;
            w += wc;
            j += 2;
            if (w.size() > 260) break;
        }
        std::string s8 = wide_to_utf8(w);
        bool looks_path = s8.find("\\") != std::string::npos &&
                          (ends_with(to_lower(s8), ".exe") || ends_with(to_lower(s8), ".dll") ||
                           ends_with(to_lower(s8), ".sys") || s8.find("\\Device\\") == 0);
        if (looks_path && s8.size() >= 8) {
            paths.push_back(s8);
            i = j; // 跳过已消费段
        }
    }
    Evidence e;
    e.source_kind = "registry";
    e.source_path = "SYSTEM\\...\\AppCompatCache(ShimCache)";
    std::string listing;
    for (const auto& p : paths) listing += p + "\n";
    e.payload = "extracted_paths=" + std::to_string(paths.size()) +
                (listing.empty() ? "" : "\n" + listing.substr(0, 48 * 1024));
    e.limitations = {"启发式路径提取（非结构化解析）；时间为 Win7 格式限制未输出——需精确解析用 AppCompatCacheParser 复核"};
    ctx.add_evidence(e);
    ctx.checked_source("AppCompatCache");
    if (!paths.empty())
        ctx.note("ShimCache 记录的是\"文件存在/被引用\"，不等于执行——结论需谨慎");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.USB：USBSTOR 设备痕迹 ----
void mod_usb(ModuleCtx& ctx) {
    const std::wstring base = L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR";
    HKEY h = open_key(HKEY_LOCAL_MACHINE, base, false);
    if (!h) { ctx.checked_source("USBSTOR [not_found]"); ctx.set_status(ModuleStatus::PASS); return; }
    std::string listing;
    int cnt = 0;
    for (const auto& dev : reg_subkeys(h)) {
        HKEY h2 = open_key(HKEY_LOCAL_MACHINE, base + L"\\" + dev, false);
        if (!h2) continue;
        for (const auto& inst : reg_subkeys(h2)) {
            std::string friendly;
            reg_get(HKEY_LOCAL_MACHINE, base + L"\\" + dev + L"\\" + inst, L"FriendlyName", false, friendly);
            ++cnt;
            listing += wide_to_utf8(dev) + " / " + wide_to_utf8(inst) +
                       (friendly.empty() ? "" : " [" + friendly + "]") + "\n";
        }
        RegCloseKey(h2);
    }
    RegCloseKey(h);
    Evidence e;
    e.source_kind = "registry";
    e.source_path = "HKLM\\" + wide_to_utf8(base);
    e.payload = "usb_devices=" + std::to_string(cnt) + (listing.empty() ? "" : "\n" + listing);
    ctx.add_evidence(e);
    ctx.checked_source("USBSTOR");
    if (cnt > 0)
        ctx.note("U 盘/移动设备接入痕迹（取证线索；时间需结合 setupapi.dev.log）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.RDPMRU：RDP 连接痕迹 ----
void mod_rdpmru(ModuleCtx& ctx) {
    const std::wstring base = L"Software\\Microsoft\\Terminal Server Client\\Servers";
    HKEY h = open_key(HKEY_CURRENT_USER, base, false);
    std::string listing;
    int cnt = 0;
    if (h) {
        for (const auto& srv : reg_subkeys(h)) {
            std::string user;
            reg_get(HKEY_CURRENT_USER, base + L"\\" + srv, L"UsernameHint", false, user);
            ++cnt;
            listing += wide_to_utf8(srv) + (user.empty() ? "" : " (user: " + user + ")") + "\n";
        }
        RegCloseKey(h);
    }
    ctx.planned_source("HKCU\\Terminal Server Client\\Servers");
    Evidence e;
    e.source_kind = "registry";
    e.source_path = "HKCU\\" + wide_to_utf8(base);
    e.payload = cnt ? ("mru=" + std::to_string(cnt) + "\n" + listing) : "(无记录)";
    e.limitations = {"仅当前用户（HKCU）痕迹；其他用户不覆盖"};
    ctx.add_evidence(e);
    ctx.checked_source("HKCU RDP MRU");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.FIREWALL：防火墙放行规则只读枚举 ----
void mod_firewall(ModuleCtx& ctx) {
    INetFwPolicy2* pol = nullptr;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool com_ok = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    if (!com_ok) { ctx.omitted_source("防火墙 COM", "CoInitializeEx 失败"); ctx.set_status(ModuleStatus::ERROR); return; }
    if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                __uuidof(INetFwPolicy2), (void**)&pol)) || !pol) {
        ctx.omitted_source("INetFwPolicy2", "COM 创建失败");
        ctx.set_status(ModuleStatus::UNSUPPORTED);
        return;
    }
    INetFwRules* rules = nullptr;
    if (FAILED(pol->get_Rules(&rules)) || !rules) {
        ctx.omitted_source("防火墙规则集", "获取失败");
        pol->Release();
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    LONG n = 0;
    rules->get_Count(&n);
    IEnumVARIANT* en = nullptr;
    IUnknown* unk = nullptr;
    std::string listing, suspects;
    int allow_enabled = 0;
    if (SUCCEEDED(rules->get__NewEnum(&unk)) && unk) {
        unk->QueryInterface(IID_IEnumVARIANT, (void**)&en);
        unk->Release();
    }
    if (en) {
        ULONG got = 0;
        VARIANT v;
        VariantInit(&v);
        int iter = 0;
        while (en->Next(1, &v, &got) == S_OK && got == 1 && iter < 800) {
            ++iter;
            if (v.vt == VT_DISPATCH && v.pdispVal) {
                INetFwRule* r = nullptr;
                if (SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&r)) && r) {
                    BSTR bn = nullptr, ba = nullptr, bp = nullptr;
                    NET_FW_ACTION act = NET_FW_ACTION_BLOCK;
                    VARIANT_BOOL en2 = VARIANT_FALSE;
                    if (SUCCEEDED(r->get_Name(&bn)) && bn) { /* name */ }
                    r->get_Action(&act);
                    r->get_Enabled(&en2);
                    if (SUCCEEDED(r->get_ApplicationName(&ba)) && ba) { /* app */ }
                    if (SUCCEEDED(r->get_LocalPorts(&bp)) && bp) { /* ports */ }
                    std::string name = bn ? wide_to_utf8(bn) : "";
                    std::string app = ba ? wide_to_utf8(ba) : "";
                    std::string ports = bp ? wide_to_utf8(bp) : "";
                    if (act == NET_FW_ACTION_ALLOW && en2 == VARIANT_TRUE) {
                        ++allow_enabled;
                        listing += "ALLOW " + name + " app=" + app.substr(0, 100) + " ports=" + ports + "\n";
                        if (!app.empty() && is_writable_path(app)) {
                            suspects += name + " → " + app + "\n";
                        }
                    }
                    if (bn) SysFreeString(bn);
                    if (ba) SysFreeString(ba);
                    if (bp) SysFreeString(bp);
                    r->Release();
                }
            }
            VariantClear(&v);
        }
        en->Release();
    }
    rules->Release();
    pol->Release();
    Evidence e;
    e.source_kind = "com";
    e.source_path = "INetFwPolicy2 放行规则";
    e.payload = "allow_enabled=" + std::to_string(allow_enabled) + "\n" + listing.substr(0, 48 * 1024);
    ctx.add_evidence(e);
    ctx.checked_source("防火墙规则");
    if (!suspects.empty()) {
        Finding f;
        f.rule_id = "WIN.FW.WRITABLEAPP.001";
        f.severity = "low";
        f.confidence = "medium";
        f.rationale = "防火墙放行规则指向可写目录程序（需核实是否用户自装）:\n" + suspects.substr(0, 800);
        f.object_ref = "Firewall";
        f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
        ctx.add_finding(f);
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.SHARES：共享枚举 ----
void mod_shares(ModuleCtx& ctx) {
    SHARE_INFO_2* buf = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS st = NetShareEnum(nullptr, 2, (LPBYTE*)&buf, MAX_PREFERRED_LENGTH,
                                     &read, &total, &resume);
    if (st != NERR_Success && st != ERROR_MORE_DATA) {
        ctx.omitted_source("NetShareEnum", last_error_str("NetShareEnum"));
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    std::string listing, suspects;
    for (DWORD i = 0; i < read; ++i) {
        std::string name = wide_to_utf8(buf[i].shi2_netname);
        std::string path = wide_to_utf8(buf[i].shi2_path);
        listing += name + " → " + path + "\n";
        bool admin_share = ends_with(name, "$");
        if (!admin_share && !path.empty() && !is_expected_path(path)) {
            suspects += name + " → " + path + "\n";
        }
    }
    NetApiBufferFree(buf);
    Evidence e;
    e.source_kind = "api";
    e.source_path = "NetShareEnum(level1)";
    e.payload = listing.empty() ? "(无共享)" : listing;
    ctx.add_evidence(e);
    ctx.checked_source("共享枚举");
    if (!suspects.empty()) {
        Finding f;
        f.rule_id = "WIN.SHARE.NONDEFAULT.001";
        f.severity = "low";
        f.confidence = "medium";
        f.rationale = "非默认共享存在（可能用于横向移动/文件投递，需核实）:\n" + suspects.substr(0, 600);
        f.object_ref = "Shares";
        f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
        ctx.add_finding(f);
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.DRIVERS：驱动服务可写路径 ----
void mod_drivers(ModuleCtx& ctx) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        ctx.omitted_source("SCM(驱动)", last_error_str("OpenSCManager"));
        ctx.set_status(ModuleStatus::PERMISSION_DENIED);
        return;
    }
    DWORD need = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER,
                          SERVICE_STATE_ALL, nullptr, 0, &need, &count, &resume, nullptr);
    std::vector<BYTE> buf(need);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER,
                               SERVICE_STATE_ALL, buf.data(), need, &need, &count, &resume, nullptr)) {
        ctx.omitted_source("驱动枚举", last_error_str("EnumServicesStatusEx"));
        CloseServiceHandle(scm);
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    auto* svc = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS*>(buf.data());
    std::string listing, suspects;
    int flagged = 0;
    for (DWORD i = 0; i < count; ++i) {
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
                std::string path = wide_to_utf8(qc->lpBinaryPathName);
                listing += name + "|" + path.substr(0, 130) + "\n";
                if (is_writable_path(path) && flagged < 20) {
                    ++flagged;
                    suspects += name + " → " + path + "\n";
                }
            }
        }
        CloseServiceHandle(h);
    }
    CloseServiceHandle(scm);
    Evidence e;
    e.source_kind = "api";
    e.source_path = "SCM 内核/文件系统驱动枚举";
    e.payload = "drivers=" + std::to_string(count) + "\n" + listing.substr(0, 64 * 1024);
    ctx.add_evidence(e);
    ctx.checked_source("驱动枚举");
    if (!suspects.empty()) {
        Finding f;
        f.rule_id = "WIN.DRV.WRITABLE.001";
        f.severity = "medium";
        f.confidence = "medium";
        f.rationale = "驱动二进制位于可写目录（内核攻击面，需重点核实）:\n" + suspects;
        f.object_ref = "Drivers";
        f.advice_id = "ADVICE.SVC.REVIEW.001";
        ctx.add_finding(f);
    }
    ctx.note("本模块只读枚举；rootkit 级隐藏不在覆盖范围（W11/内核专题 DEFERRED）");
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_w3(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"WIN.PREFETCH", "1.0.0", "windows", [](ModuleCtx& c) { mod_prefetch(c); }});
    mods.push_back({"WIN.SHIMCACHE", "1.0.0", "windows", [](ModuleCtx& c) { mod_shimcache(c); }});
    mods.push_back({"WIN.USB", "1.0.0", "windows", [](ModuleCtx& c) { mod_usb(c); }});
    mods.push_back({"WIN.RDPMRU", "1.0.0", "windows", [](ModuleCtx& c) { mod_rdpmru(c); }});
    mods.push_back({"WIN.FIREWALL", "1.0.0", "windows", [](ModuleCtx& c) { mod_firewall(c); }});
    mods.push_back({"WIN.SHARES", "1.0.0", "windows", [](ModuleCtx& c) { mod_shares(c); }});
    mods.push_back({"WIN.DRIVERS", "1.0.0", "windows", [](ModuleCtx& c) { mod_drivers(c); }});
}

} // namespace ctfir::win
