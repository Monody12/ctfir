#include "util.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <random>
#include <cstring>

namespace ctfir {

static std::string format_gmtime(std::time_t t) {
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

std::string now_utc_iso8601() {
    return format_gmtime(std::time(nullptr));
}

// 极简 ISO8601(Z) 解析：YYYY-MM-DDTHH:MM:SSZ
static bool parse_utc_iso(const std::string& s, std::time_t& out) {
    int y, mo, d, h, mi, sec;
    if (s.size() < 20 || s[19] != 'Z') return false;
    if (std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ", &y, &mo, &d, &h, &mi, &sec) != 6)
        return false;
    std::tm tmv{};
    tmv.tm_year = y - 1900; tmv.tm_mon = mo - 1; tmv.tm_mday = d;
    tmv.tm_hour = h; tmv.tm_min = mi; tmv.tm_sec = sec; tmv.tm_isdst = 0;
#if defined(_WIN32)
    out = _mkgmtime(&tmv);
#else
    out = timegm(&tmv);
#endif
    return out != static_cast<std::time_t>(-1);
}

std::string beijing_time_str(const std::string& utc_iso) {
    std::time_t t;
    if (!parse_utc_iso(utc_iso, t)) return utc_iso + " (raw)";
    return format_gmtime(t + 8 * 3600).substr(0, 10) + " " +
           format_gmtime(t + 8 * 3600).substr(11, 8) + " (UTC+8)";
}

std::string random_id(const std::string& prefix) {
    std::random_device rd;
    unsigned long long a = (static_cast<unsigned long long>(rd()) << 32) ^ rd();
    unsigned long long b = (static_cast<unsigned long long>(rd()) << 32) ^ rd();
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%s-%016llx%016llx", prefix.c_str(),
                  static_cast<unsigned long long>(a), static_cast<unsigned long long>(b));
    return buf;
}

std::string to_lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

bool contains_ci(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    const std::string h = to_lower(hay), n = to_lower(needle);
    return h.find(n) != std::string::npos;
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool ends_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '\n') {
            std::string line = s.substr(start, i - start);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            out.push_back(line);
            start = i + 1;
        }
    }
    // 以换行结尾的输入不产生尾空行
    if (!out.empty() && !s.empty() && s.back() == '\n' && out.back().empty()) out.pop_back();
    return out;
}

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

bool is_valid_utf8(const std::string& s) {
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) { ++i; continue; }
        int len; unsigned int cp;
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
        else return false;
        if (i + len > n) return false;
        for (int k = 1; k < len; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        // 过长编码与代理区/越界拒绝
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) ||
            (len == 4 && cp < 0x10000) || cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        i += len;
    }
    return true;
}

std::string escape_html(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char ch : s) {
        switch (ch) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        case '\0': out += "\\0"; break;
        default: out += ch;
        }
    }
    return out;
}

std::string sanitize_utf8(const std::string& s) {
    if (is_valid_utf8(s)) return s;
    std::string out;
    out.reserve(s.size() + 16);
    size_t i = 0, n = s.size();
    while (i < n) {
        // 找出下一个合法 UTF-8 起点：逐字节试探
        unsigned char c = static_cast<unsigned char>(s[i]);
        int len = 0;
        if (c < 0x80) len = 1;
        else if ((c & 0xE0) == 0xC0) len = 2;
        else if ((c & 0xF0) == 0xE0) len = 3;
        else if ((c & 0xF8) == 0xF0) len = 4;
        bool ok = false;
        if (len > 0 && i + len <= n) {
            std::string cand = s.substr(i, len);
            ok = is_valid_utf8(cand);
        }
        if (ok) { out += s.substr(i, static_cast<size_t>(len)); i += static_cast<size_t>(len); }
        else {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\x%02X", c);
            out += buf;
            ++i;
        }
    }
    return out;
}

bool base64_decode(const std::string& in, std::string& out) {
    // 计算式映射（避免手打表错误）：A-Z→0-25, a-z→26-51, 0-9→52-61, '+'→62, '/'→63
    auto b64val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    int pad_seen = 0;
    for (char ch : in) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') { ++pad_seen; continue; }
        if (pad_seen) return false; // 填充后又出现数据
        int v = b64val(c);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return true;
}

} // namespace ctfir
