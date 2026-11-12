#pragma once
// 离线 Web/数据库日志攻击特征匹配（只读、无网络）。
// 供 Linux / Windows 采集模块与单测共用：URL 解码、SQLi / 目录穿越 /
// webshell 访问 / 扫描器 UA、PowerShell 历史、ADS 良性流、MySQL 日志关键字、
// 宝塔访问日志文件名判定、combined 日志解析。
#include "util.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ctfir {

inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 百分号解码；非法序列原样保留。'+' 按查询串惯例译为空格。
inline std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int hi = hex_nibble(s[i + 1]);
            int lo = hex_nibble(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i] == '+' ? ' ' : s[i]);
    }
    return out;
}

inline std::string url_decode_twice(const std::string& s) {
    return url_decode(url_decode(s));
}

enum class LogAttackKind { Sqli, Traversal, Webshell, ScannerUa };

struct LogAttackMatch {
    LogAttackKind kind;
    const char* why;
};

inline const char* log_attack_kind_str(LogAttackKind k) {
    switch (k) {
        case LogAttackKind::Sqli: return "SQLi";
        case LogAttackKind::Traversal: return "目录穿越";
        case LogAttackKind::Webshell: return "webshell 访问";
        case LogAttackKind::ScannerUa: return "扫描器 UA";
    }
    return "?";
}

inline bool has_sub(const std::string& hay, const char* n) {
    return hay.find(n) != std::string::npos;
}

// uri_l / ua_l：调用方已 to_lower；本函数再对 uri 做双重解码后匹配。
inline std::vector<LogAttackMatch> match_log_attack(const std::string& /*method*/,
                                                    const std::string& uri_or_query,
                                                    const std::string& ua) {
    std::vector<LogAttackMatch> hits;
    std::string uri_l = to_lower(url_decode_twice(uri_or_query));
    std::string ua_l = to_lower(ua);

    auto add_once = [&](LogAttackKind k, const char* why, bool cond) {
        if (!cond) return;
        for (const auto& h : hits)
            if (h.kind == k) return;
        hits.push_back({k, why});
    };

    add_once(LogAttackKind::Sqli, "UNION SELECT / information_schema 等注入特征",
             has_sub(uri_l, "union select") || has_sub(uri_l, "union all select") ||
                 has_sub(uri_l, "information_schema") || has_sub(uri_l, "extractvalue(") ||
                 has_sub(uri_l, "updatexml(") || has_sub(uri_l, "xp_cmdshell"));
    add_once(LogAttackKind::Sqli, "时间盲注/文件读写函数",
             has_sub(uri_l, "sleep(") || has_sub(uri_l, "benchmark(") ||
                 has_sub(uri_l, "load_file(") || has_sub(uri_l, "into outfile") ||
                 has_sub(uri_l, "into dumpfile"));
    add_once(LogAttackKind::Sqli, "经典恒真注入探针",
             has_sub(uri_l, "and 1=1") || has_sub(uri_l, "or 1=1") ||
                 has_sub(uri_l, "or '1'='1") || has_sub(uri_l, "or \"1\"=\"1") ||
                 has_sub(uri_l, "' or '") || has_sub(uri_l, "and 1=2"));

    // 解码后出现 ../ 或 ..\ ，或残留双重编码痕迹
    add_once(LogAttackKind::Traversal, "目录穿越 ../ 或编码变体",
             has_sub(uri_l, "../") || has_sub(uri_l, "..\\") || has_sub(uri_l, "..\\/") ||
                 has_sub(uri_or_query, "%2e%2e") || has_sub(uri_or_query, "%252e"));

    // 常见 webshell 文件名被访问（CTF / 真实入侵高频）
    static const char* shells[] = {
        "/shell.php", "/cmd.php", "/c99.php", "/wso.php", "/weevely",
        "/chopper", "/godzilla", "/behinder", "/caidao", "/antsword",
        "/shell.jsp", "/cmd.jsp", "/cmd.aspx", "/shell.aspx", "/1.jsp",
        "/hack.php", "/webshell.", "/eval.php", "/minishell",
        "/shell.asp", "/cmd.asp",
    };
    bool sh = false;
    for (const char* s : shells) {
        if (has_sub(uri_l, s)) { sh = true; break; }
    }
    add_once(LogAttackKind::Webshell, "请求命中常见 webshell 文件名", sh);

    static const char* uas[] = {
        "sqlmap", "nikto", "nmap", "masscan", "nuclei", "dirbuster",
        "gobuster", "wfuzz", "acunetix", "nessus", "openvas", "wpscan",
        "havij", "dirmap", "feroxbuster", "ffuf/", "zaproxy", "whatweb",
        "nessus", "w3af",
    };
    bool ua_hit = false;
    for (const char* u : uas) {
        if (has_sub(ua_l, u)) { ua_hit = true; break; }
    }
    add_once(LogAttackKind::ScannerUa, "User-Agent 命中扫描器默认标识", ua_hit);
    return hits;
}

// combined / common 日志：IP ... "METHOD PATH PROTO" status size "ref" "UA"
struct CombinedLogLine {
    std::string ip, method, uri, ua;
    bool ok = false;
};

inline CombinedLogLine parse_combined_log_line(const std::string& line) {
    CombinedLogLine r;
    if (line.empty() || line[0] == '#') return r;
    std::string ip;
    size_t sp = line.find(' ');
    if (sp == std::string::npos) return r;
    ip = line.substr(0, sp);
    size_t q1 = line.find('"');
    if (q1 == std::string::npos) return r;
    size_t q2 = line.find('"', q1 + 1);
    if (q2 == std::string::npos) return r;
    std::string req = line.substr(q1 + 1, q2 - q1 - 1);
    std::string method, uri;
    size_t s1 = req.find(' ');
    if (s1 == std::string::npos) return r;
    method = req.substr(0, s1);
    size_t s2 = req.find(' ', s1 + 1);
    uri = (s2 == std::string::npos) ? req.substr(s1 + 1) : req.substr(s1 + 1, s2 - s1 - 1);
    std::string ua;
    size_t q3 = line.rfind('"');
    if (q3 != std::string::npos && q3 > q2) {
        size_t q4 = line.rfind('"', q3 - 1);
        if (q4 != std::string::npos && q4 > q2) ua = line.substr(q4 + 1, q3 - q4 - 1);
    }
    r.ip = ip;
    r.method = method;
    r.uri = uri;
    r.ua = ua;
    r.ok = !ip.empty() && !method.empty();
    return r;
}

struct AccessLogSummary {
    int posts = 0;
    std::map<std::string, int> post_ip;
    int attack_hits = 0;
    std::map<std::string, int> attack_ip;          // ip -> count
    std::map<std::string, int> attack_kind;        // kind str -> count
    std::vector<std::string> samples;              // 最多 8 条样本
};

inline void consume_access_request(AccessLogSummary& s, const std::string& ip,
                                   const std::string& method, const std::string& uri,
                                   const std::string& ua) {
    if (method == "POST") {
        ++s.posts;
        if (!ip.empty()) ++s.post_ip[ip];
    }
    auto hits = match_log_attack(method, uri, ua);
    if (hits.empty()) return;
    ++s.attack_hits;
    if (!ip.empty()) ++s.attack_ip[ip];
    for (const auto& h : hits) ++s.attack_kind[log_attack_kind_str(h.kind)];
    if (s.samples.size() < 8) {
        std::string why;
        for (size_t i = 0; i < hits.size(); ++i) {
            if (i) why += "/";
            why += log_attack_kind_str(hits[i].kind);
        }
        s.samples.push_back(ip + " " + method + " " + uri.substr(0, 120) + " [" + why + "]");
    }
}

inline void consume_combined_line(AccessLogSummary& s, const std::string& line) {
    CombinedLogLine r = parse_combined_log_line(line);
    if (!r.ok) return;
    consume_access_request(s, r.ip, r.method, r.uri, r.ua);
}

inline std::string top_ip_str(const std::map<std::string, int>& m, int cap = 8) {
    std::vector<std::pair<int, std::string>> v;
    for (const auto& kv : m) v.push_back({kv.second, kv.first});
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.first > b.first; });
    std::string out;
    for (int i = 0; i < static_cast<int>(v.size()) && i < cap; ++i)
        out += v[i].second + "×" + std::to_string(v[i].first) + " ";
    return out;
}

// PowerShell 历史可疑命令（PSReadLine ConsoleHost_history.txt）
inline bool ps_hist_suspicious(const std::string& line) {
    std::string low = to_lower(line);
    auto has = [&](const char* t) { return contains_ci(low, t); };
    if (has("-enc") || has("encodedcommand") || has("downloadstring") ||
        has("downloadfile") || has("invoke-expression") || has("iex ") ||
        has("iex(") || has("iex .") || has("net.webclient") ||
        has("frombase64string") || has("invoke-webrequest") ||
        has("invoke-restmethod") || has("certutil -urlcache") ||
        has("certutil -decode") || has("bitsadmin /transfer") ||
        has("executionpolicy bypass") || has("-ep bypass") ||
        has("-w hidden") || has("-windowstyle hidden") ||
        has("add-mppreference") || has("invoke-mimikatz") ||
        has("sekurlsa") || has("lsass"))
        return true;
    if (has("whoami") && (has("priv") || has("/all"))) return true;
    return false;
}

// NTFS ADS：Zone.Identifier 等系统良性流不报（否则 Downloads 会被刷屏）
inline bool ads_stream_benign(const std::string& stream_name) {
    std::string s = to_lower(stream_name);
    if (s == "::$data" || s.empty()) return true; // 主数据流
    static const char* benign[] = {
        "zone.identifier", "smartscreen", "encryptable", "favicon",
        "afp_afpinfo", "afp_resource", "com.dropbox", "com.apple",
        "ocdownload", "outlook", "compatibility", "widestreams",
        "{4c8cc155", "xorwow", "ms-properties",
    };
    for (const char* b : benign)
        if (s.find(b) != std::string::npos) return true;
    return false;
}

// MySQL general/slow/binlog（文本或 STATEMENT 明文）可疑 SQL
inline bool mysql_log_suspicious(const std::string& line, std::string* why = nullptr) {
    std::string low = to_lower(line);
    auto hit = [&](const char* t, const char* w) {
        if (low.find(t) == std::string::npos) return false;
        if (why) *why = w;
        return true;
    };
    if (hit("into outfile", "INTO OUTFILE 写文件")) return true;
    if (hit("into dumpfile", "INTO DUMPFILE 写文件")) return true;
    if (hit("create function", "CREATE FUNCTION（UDF 提权）")) return true;
    if (hit("sys_eval", "sys_eval UDF")) return true;
    if (hit("sys_exec", "sys_exec UDF")) return true;
    if (hit("sys_system", "sys_system UDF")) return true;
    if (hit("load_file(", "LOAD_FILE 读文件")) return true;
    return false;
}

// 宝塔 / 通用站点访问日志文件名：接受 *.log / *access* ，排除 error
inline bool is_web_access_log_name(const std::string& path) {
    std::string base = path;
    size_t sl = base.find_last_of("/\\");
    if (sl != std::string::npos) base = base.substr(sl + 1);
    std::string b = to_lower(base);
    if (b.find("error") != std::string::npos) return false;
    if (ends_with(b, ".gz") || ends_with(b, ".zip") || ends_with(b, ".swp")) return false;
    if (ends_with(b, ".log") || ends_with(b, "_log") || ends_with(b, "-access_log"))
        return true;
    if (b.find("access") != std::string::npos &&
        (ends_with(b, ".log") || ends_with(b, "_log") || b.find(".log") != std::string::npos))
        return true;
    return false;
}

} // namespace ctfir
