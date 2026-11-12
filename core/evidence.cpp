#include "evidence.hpp"
#include "util.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace ctfir {

ReadResult read_text_file(const std::string& utf8_path, size_t max_bytes) {
    ReadResult r;
#if defined(_WIN32)
    std::ifstream f(fs::u8path(utf8_path), std::ios::binary);
#else
    std::ifstream f(utf8_path, std::ios::binary);
#endif
    if (!f) {
        // errno 精确分类：父目录不可读时 exists() 会误报 not_found（fault 例关键路径）
        // errno 必须在失败 open 之后、任何其他调用之前读取
        int e = errno;
        r.error_detail = std::string("open failed (errno=") + std::to_string(e) + ")";
#if defined(_WIN32)
        (void)e;
        std::error_code ec;
        r.access_status = fs::exists(fs::u8path(utf8_path), ec) ? "denied" : "not_found";
        if (ec) r.access_status = "error";
#else
        if (e == ENOENT) r.access_status = "not_found";
        else if (e == EACCES || e == EPERM) r.access_status = "denied";
        else if (e == ELOOP) r.access_status = "error";  // 符号链接环
        else r.access_status = "error";
#endif
        return r;
    }
    std::string raw;
    char buf[65536];
    bool cap_hit = false;
    while (raw.size() < max_bytes) {
        f.read(buf, sizeof(buf));
        std::streamsize got = f.gcount();
        if (got <= 0) break;
        size_t take = static_cast<size_t>(got);
        if (raw.size() + take > max_bytes) {
            take = max_bytes - raw.size();
            raw.append(buf, take);
            cap_hit = true;
            break;
        }
        raw.append(buf, take);
    }
    if (!cap_hit && raw.size() >= max_bytes) {
        char probe;
        if (f.get(probe)) cap_hit = true;
    }
    if (f.bad()) { r.access_status = "error"; r.error_detail = "read failed"; return r; }

    r.raw_size = raw.size();
    r.raw_sha256 = Sha256::hex_of(raw.data(), raw.size());
    r.ok = true;
    r.access_status = cap_hit ? "partial" : "ok";
    r.truncated = cap_hit;

    if (raw.empty()) { r.encoding = "empty"; r.content.clear(); return r; }
    if (raw.size() >= 3 && (unsigned char)raw[0] == 0xEF && (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF) {
        r.encoding = "utf8_bom";
        r.content = raw.substr(3);
        if (!is_valid_utf8(r.content)) r.encoding = "non_utf8_raw";
        return r;
    }
    if (raw.size() >= 2 && (unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE) {
        r.encoding = "utf16le";
        std::string out;
        for (size_t i = 2; i + 1 < raw.size(); i += 2) {
            uint32_t u = (unsigned char)raw[i] | ((unsigned char)raw[i+1] << 8);
            if (u >= 0xD800 && u <= 0xDBFF && i + 3 < raw.size()) {
                uint32_t lo = (unsigned char)raw[i+2] | ((unsigned char)raw[i+3] << 8);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                    i += 2;
                }
            }
            if (u < 0x80) out += (char)u;
            else if (u < 0x800) { out += (char)(0xC0 | (u >> 6)); out += (char)(0x80 | (u & 0x3F)); }
            else if (u < 0x10000) { out += (char)(0xE0 | (u >> 12)); out += (char)(0x80 | ((u >> 6) & 0x3F)); out += (char)(0x80 | (u & 0x3F)); }
            else { out += (char)(0xF0 | (u >> 18)); out += (char)(0x80 | ((u >> 12) & 0x3F)); out += (char)(0x80 | ((u >> 6) & 0x3F)); out += (char)(0x80 | (u & 0x3F)); }
        }
        r.content = out;
        return r;
    }
    if (is_valid_utf8(raw)) { r.encoding = "utf8"; r.content = raw; return r; }
    r.encoding = "non_utf8_raw";
    r.content = raw; // 原字节保留；payload 落库前过 sanitize_utf8
    return r;
}

bool dir_readable(const std::string& utf8_path) {
    std::error_code ec;
    fs::path p = fs::u8path(utf8_path);
    if (!fs::is_directory(p, ec)) return false;
    fs::directory_iterator it(p, ec);
    return !ec;
}

} // namespace ctfir
