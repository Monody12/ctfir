#pragma once
// AD / Windows Server 考点的纯文本判定（无网络、不解密、不解析 NTDS 哈希）。
// 供 Windows 采集模块与双平台单测共用。
#include "util.hpp"

#include <string>
#include <vector>

namespace ctfir {

// UTF-16 LE（含无 BOM 的 INF）转成可搜索 ASCII/UTF-8。安全模板常是 UTF-16。
inline std::string normalize_ad_text(const std::string& raw) {
    if (raw.size() < 2) return raw;
    size_t start = 0;
    bool utf16 = false;
    if ((unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE) {
        utf16 = true;
        start = 2;
    } else {
        size_t nuls = 0;
        for (char c : raw)
            if (c == 0) ++nuls;
        if (nuls > raw.size() / 4) utf16 = true;
    }
    if (!utf16) return raw;
    std::string out;
    out.reserve(raw.size() / 2);
    for (size_t i = start; i + 1 < raw.size(); i += 2) {
        unsigned char lo = static_cast<unsigned char>(raw[i]);
        unsigned char hi = static_cast<unsigned char>(raw[i + 1]);
        if (hi == 0) out.push_back(static_cast<char>(lo));
    }
    return out;
}

// ---- GPP cpassword（MS14-025 / T1552.006）----
// 只判断属性存在且非空。AES 密钥公开可解密，但红线禁止落明文口令。
inline bool xml_has_cpassword(const std::string& xml) {
    std::string l = to_lower(normalize_ad_text(xml));
    size_t p = 0;
    while ((p = l.find("cpassword", p)) != std::string::npos) {
        size_t eq = l.find('=', p + 9);
        if (eq == std::string::npos) break;
        bool only_ws = true;
        for (size_t i = p + 9; i < eq; ++i) {
            char c = l[i];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                only_ws = false;
                break;
            }
        }
        if (only_ws) {
            size_t q = eq + 1;
            while (q < l.size() && (l[q] == ' ' || l[q] == '\t')) ++q;
            if (q < l.size() && (l[q] == '"' || l[q] == '\'')) {
                char quote = l[q];
                size_t e = l.find(quote, q + 1);
                if (e != std::string::npos && e > q + 1) return true;
            }
        }
        p += 9;
    }
    return false;
}

// GPO 首选项立即任务 / 计划任务：出现 Exec/Command 即视为可落地的持久化。
inline bool xml_has_gpo_exec(const std::string& xml) {
    std::string l = to_lower(normalize_ad_text(xml));
    if (l.find("<exec") != std::string::npos) return true;
    if (l.find("<command") != std::string::npos) return true;
    size_t p = l.find("command=\"");
    if (p != std::string::npos) {
        size_t e = l.find('"', p + 9);
        if (e != std::string::npos && e > p + 9) return true;
    }
    return false;
}

// ---- ntds.dit 路径分类 ----
enum class NtdsClass { None, Live, Copy, Ifm };

inline std::string path_basename_lower(const std::string& path) {
    std::string l = to_lower(path);
    size_t sl = l.find_last_of("\\/");
    return sl == std::string::npos ? l : l.substr(sl + 1);
}

inline bool looks_like_ntds_filename(const std::string& base) {
    std::string b = to_lower(base);
    if (b == "ntds.dit" || b == "ntds.dit.bak" || b == "ntds.dit.old") return true;
    // 赛题/取证常见改名：ntds-copy.dit、ctfir-marker-ntds.dit、ntds.dit.bak
    if (b.find("ntds") == std::string::npos) return false;
    return ends_with(b, ".dit") || ends_with(b, ".dit.bak") || ends_with(b, ".dit.old");
}

inline std::string path_norm_lower(const std::string& path) {
    std::string l = to_lower(path);
    for (char& c : l)
        if (c == '/') c = '\\';
    while (l.size() >= 2 && l[l.size() - 1] == '\\') l.pop_back();
    return l;
}

inline NtdsClass classify_ntds_path(const std::string& path, const std::string& windows_dir) {
    std::string base = path_basename_lower(path);
    if (!looks_like_ntds_filename(base)) return NtdsClass::None;
    std::string l = path_norm_lower(path);
    if (l.find("\\active directory\\") != std::string::npos)
        return NtdsClass::Ifm;
    std::string w = path_norm_lower(windows_dir);
    if (base == "ntds.dit" && !w.empty() && l == w + "\\ntds\\ntds.dit")
        return NtdsClass::Live;
    return NtdsClass::Copy;
}

// T1003.002：reg save / secretsdump 留下的 SAM/SYSTEM/SECURITY 副本。
// 活动库在 system32\config（含 RegBack）与 windows\repair，不当副本。
inline bool looks_like_hive_filename(const std::string& base) {
    std::string b = to_lower(base);
    if (b == "sam.save" || b == "system.save" || b == "security.save") return true;
    if (b == "sam.hiv" || b == "system.hiv" || b == "security.hiv") return true;
    if (b == "sam.bak" || b == "system.bak" || b == "security.bak") return true;
    if (ends_with(b, ".save") || ends_with(b, ".hiv")) {
        if (b.find("sam") != std::string::npos) return true;
        if (b.find("security") != std::string::npos) return true;
        if (b.find("system") != std::string::npos) return true;
    }
    return b == "sam" || b == "security" || b == "system";
}

inline bool is_live_hive_path(const std::string& path) {
    std::string l = path_norm_lower(path);
    if (l.find("\\system32\\config") != std::string::npos) return true;
    if (l.find("\\syswow64\\config") != std::string::npos) return true;
    if (l.find("\\windows\\repair\\") != std::string::npos) return true;
    return false;
}

inline bool looks_like_hive_copy_path(const std::string& path) {
    if (is_live_hive_path(path)) return false;
    std::string b = path_basename_lower(path);
    if (!looks_like_hive_filename(b)) return false;
    if (b == "sam" || b == "system" || b == "security") {
        std::string l = path_norm_lower(path);
        return l.find("\\temp\\") != std::string::npos ||
               l.find("\\users\\") != std::string::npos ||
               l.find("\\registry\\") != std::string::npos ||
               l.find("\\ifm") != std::string::npos ||
               l.find("\\public\\") != std::string::npos ||
               l.find("\\desktop\\") != std::string::npos ||
               l.find("\\documents\\") != std::string::npos ||
               l.find("\\downloads\\") != std::string::npos;
    }
    return true;
}

// T1003.001：lsass 转储（Task Manager / procdump / comsvcs MiniDump）。
inline bool looks_like_lsass_dump(const std::string& path) {
    std::string b = path_basename_lower(path);
    if (b.find("lsass") == std::string::npos) return false;
    return ends_with(b, ".dmp") || ends_with(b, ".mdmp") || ends_with(b, ".dump");
}

inline bool is_sysvol_script_name(const std::string& path) {
    std::string b = path_basename_lower(path);
    return ends_with(b, ".bat") || ends_with(b, ".cmd") || ends_with(b, ".vbs") ||
           ends_with(b, ".ps1") || ends_with(b, ".js") || ends_with(b, ".exe") ||
           ends_with(b, ".wsf") || ends_with(b, ".vbe");
}

inline bool path_looks_like_sysvol_scripts(const std::string& path) {
    std::string l = path_norm_lower(path);
    return l.find("\\scripts\\") != std::string::npos ||
           l.find("\\netlogon\\") != std::string::npos;
}

// ProgramData 等噪音目录只处理可能含考点的文件，避免 500 文件预算被吃光。
inline bool ad_file_candidate(const std::string& path) {
    std::string b = path_basename_lower(path);
    if (looks_like_ntds_filename(b)) return true;
    if (looks_like_hive_copy_path(path)) return true;
    if (looks_like_lsass_dump(path)) return true;
    if (ends_with(b, ".xml") || ends_with(b, ".inf") || ends_with(b, ".ini")) return true;
    if (is_sysvol_script_name(path) && path_looks_like_sysvol_scripts(path)) return true;
    return false;
}

// GptTmpl.inf：指定特权含非 Administrators 即扩大。
inline bool gptmpl_extra_privilege(const std::string& inf, const char* priv_name,
                                   std::string* extra_out = nullptr) {
    std::string want = to_lower(std::string(priv_name ? priv_name : ""));
    if (want.empty()) return false;
    auto lines = split_lines(normalize_ad_text(inf));
    for (const auto& raw : lines) {
        std::string line = trim(raw);
        if (line.empty() || line[0] == ';') continue;
        std::string l = to_lower(line);
        if (l.find(want) != 0) continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string rhs = trim(line.substr(eq + 1));
        std::string extra;
        std::string tok;
        auto flush = [&]() {
            std::string t = trim(tok);
            tok.clear();
            if (t.empty()) return;
            std::string tl = to_lower(t);
            if (tl == "*s-1-5-32-544" || tl == "s-1-5-32-544" || tl == "administrators")
                return;
            if (!extra.empty()) extra += ",";
            extra += t;
        };
        for (char c : rhs) {
            if (c == ',') flush();
            else tok.push_back(c);
        }
        flush();
        if (!extra.empty()) {
            if (extra_out) *extra_out = extra;
            return true;
        }
    }
    return false;
}

inline bool gptmpl_extra_delegation(const std::string& inf, std::string* extra_out = nullptr) {
    return gptmpl_extra_privilege(inf, "SeEnableDelegationPrivilege", extra_out);
}

// 委派 / Debug / TCB / Impersonate 任一扩大即命中。
inline bool gptmpl_dangerous_extra(const std::string& inf, std::string* extra_out = nullptr) {
    const char* privs[] = {
        "SeEnableDelegationPrivilege",
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeImpersonatePrivilege",
    };
    std::string all;
    for (const char* p : privs) {
        std::string extra;
        if (gptmpl_extra_privilege(inf, p, &extra)) {
            if (!all.empty()) all += "; ";
            all += std::string(p) + "=" + extra;
        }
    }
    if (all.empty()) return false;
    if (extra_out) *extra_out = all;
    return true;
}

// GPP Groups.xml 把账户加进 Administrators（即使没有 cpassword）。
inline bool xml_has_gpp_local_admin(const std::string& xml) {
    std::string l = to_lower(normalize_ad_text(xml));
    if (l.find("administrators") == std::string::npos) return false;
    if (l.find("groupname=\"administrators\"") != std::string::npos) return true;
    if (l.find("groupname='administrators'") != std::string::npos) return true;
    if (l.find("groupsid=\"s-1-5-32-544\"") != std::string::npos) return true;
    if (l.find("<group") != std::string::npos &&
        (l.find("username=") != std::string::npos || l.find("<member") != std::string::npos))
        return true;
    return false;
}

// GPO scripts.ini：Logon/Logoff/Startup/Shutdown 的 CmdLine 非空。
inline bool scripts_ini_has_cmdline(const std::string& ini, std::string* cmd_out = nullptr) {
    auto lines = split_lines(normalize_ad_text(ini));
    for (const auto& raw : lines) {
        std::string line = trim(raw);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        std::string l = to_lower(line);
        size_t eq = l.find("cmdline=");
        if (eq == std::string::npos) continue;
        // 允许 "0CmdLine=" / "CmdLine="
        bool prefix_ok = true;
        for (size_t i = 0; i < eq; ++i) {
            char c = l[i];
            if (c >= '0' && c <= '9') continue;
            prefix_ok = false;
            break;
        }
        if (!prefix_ok) continue;
        std::string val = trim(line.substr(eq + 8));
        if (val.size() >= 2 && ((val.front() == '"' && val.back() == '"') ||
                                (val.front() == '\'' && val.back() == '\'')))
            val = val.substr(1, val.size() - 2);
        if (!val.empty()) {
            if (cmd_out) *cmd_out = val;
            return true;
        }
    }
    return false;
}

} // namespace ctfir
