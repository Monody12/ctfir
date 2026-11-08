#pragma once
// 证据采集与安全文件读取。
// 纪律：只读打开（share-deny-none）；大小上限；不跟随符号链接由遍历方保证（v1 只按显式路径读）；
// 编码探测：UTF-8 / UTF-8 BOM / UTF-16LE(BOM) / 非 UTF-8 保留原字节并标注。
#include <string>
#include "sha256.hpp"

namespace ctfir {

struct ReadResult {
    bool ok = false;
    std::string access_status;      // ok / not_found / denied / error / too_large_hit_cap
    std::string error_detail;
    std::string content;            // 解码文本（非 UTF-8 时为原字节，已标注）
    std::string raw_sha256;
    unsigned long long raw_size = 0;
    std::string encoding;           // utf8 / utf8_bom / utf16le / non_utf8_raw / empty
    bool truncated = false;
};

// max_bytes：读取上限（超出部分截断并标注 truncated，不抛错）
ReadResult read_text_file(const std::string& utf8_path, size_t max_bytes = 8 * 1024 * 1024);

// 目录是否存在 / 可读（轻探针，用于模块 UNSUPPORTED / omitted 判定）
bool dir_readable(const std::string& utf8_path);

} // namespace ctfir
