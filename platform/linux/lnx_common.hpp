#pragma once
// Linux 平台共享助手（仅供 platform/linux 内部使用）
#include "core/session.hpp"
#include "core/evidence.hpp"
#include "core/util.hpp"

#include <algorithm>
#include <dirent.h>
#include <fstream>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace ctfir::lnx {

// 注册入口（mod_a.cpp / mod_b.cpp 各自实现）
void register_mods_a(std::vector<Session::ModuleDef>& mods);
void register_mods_b(std::vector<Session::ModuleDef>& mods);

// 可疑令牌（文本规则 v1：简单子串匹配，避免无界正则；误报边界在 finding 说明中给出）
struct Tok { const char* t; const char* why; };
inline const Tok kSuspicious[] = {
    {"/tmp/", "临时目录路径"},
    {"/dev/shm", "共享内存目录路径"},
    {"wget ", "下载器特征"},
    {"curl ", "下载器/网络访问特征"},
    {"base64 -d", "base64 解码执行特征"},
    {"python -c", "内联脚本执行特征"},
    {"perl -e", "内联脚本执行特征"},
    {"nc -e", "反弹 shell 特征"},
    {"/bin/bash -i", "交互反弹 shell 特征"},
    {"mkfifo", "管道后门特征"},
    {"chmod 777", "全开放权限修改"},
    {"stratum+tcp", "矿池协议特征"},
    {"stratum+ssl", "矿池协议特征"},
    {"xmrig", "矿机程序特征"},
    {"kdevtmpfsi", "挖矿木马特征"},
    {"kinsing", "挖矿木马特征"},
    {"cryptonight", "挖矿算法特征"},
    {"bitsadmin", "下载器特征"},
    {"powershell -enc", "编码命令执行特征"},
};

inline std::vector<std::pair<std::string, std::string>> match_tokens(const std::string& text) {
    std::vector<std::pair<std::string, std::string>> hits;
    for (const auto& k : kSuspicious)
        if (contains_ci(text, k.t)) hits.emplace_back(k.t, k.why);
    return hits;
}

// 读一个来源并登记证据（required=false 时 not_found 记 omitted 而不报错）
// 返回 ReadResult（ok=false 时调用方跳过解析）
inline ReadResult read_source(ModuleCtx& ctx, const std::string& path, bool required,
                              size_t max_bytes = 1024 * 1024) {
    ctx.planned_source(path);
    ReadResult r = read_text_file(path, max_bytes);
    if (r.ok) {
        Evidence e;
        e.source_kind = "file";
        e.source_path = path;
        e.sha256 = r.raw_sha256;
        e.access_status = r.access_status;
        e.payload = r.content.size() > 64 * 1024
                        ? r.content.substr(0, 64 * 1024) + "\n...[截断展示]"
                        : r.content;
        if (r.truncated) e.limitations.push_back("内容超展示上限，原始留证为准");
        ctx.add_evidence(e);
        ctx.checked_source(path);
    } else if (r.access_status == "not_found") {
        if (required) ctx.omitted_source(path, "not_found（该来源在本机不存在）");
        else ctx.checked_source(path + " [not_found]");
    } else if (r.access_status == "denied") {
        ctx.omitted_source(path, "PERMISSION_DENIED");
    } else {
        ctx.omitted_source(path, "error: " + r.error_detail);
    }
    return r;
}

// 目录枚举（不跟随符号链接；cap 上限）
inline std::vector<std::string> list_dir(const std::string& dir, size_t cap = 500,
                                         bool* truncated = nullptr) {
    std::vector<std::string> out;
    DIR* d = opendir(dir.c_str());
    if (!d) return out;
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        std::string name = de->d_name;
        if (name == "." || name == "..") continue;
        if (out.size() >= cap) { if (truncated) *truncated = true; break; }
        out.push_back(dir + "/" + name);
    }
    closedir(d);
    std::sort(out.begin(), out.end());
    return out;
}

inline bool file_exists(const std::string& p) {
    struct stat st{};
    return lstat(p.c_str(), &st) == 0;
}

// 行遍历（带行号回调）：cb(line_no, line)
template <typename F>
inline void for_each_line(const std::string& content, F cb) {
    auto lines = split_lines(content);
    for (size_t i = 0; i < lines.size(); ++i) cb(i + 1, lines[i]);
}

inline std::string first_field(const std::string& s, size_t n) {
    std::istringstream is(s);
    std::string w;
    for (size_t i = 0; i < n; ++i) {
        if (!(is >> w)) return "";
    }
    return w;
}

} // namespace ctfir::lnx
