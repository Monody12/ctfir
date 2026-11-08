#pragma once
// ctfir 通用工具：时间（UTC 存储 / 北京时间展示）、ID、字符串。
// 时间纪律：证据时间一律 ISO8601 UTC（Z）保存原始时刻；展示层转北京时间(UTC+8)。
#include <string>
#include <vector>

namespace ctfir {

// 当前 UTC 时间，ISO8601：2026-11-08T12:34:56Z
std::string now_utc_iso8601();

// 由 UTC ISO8601 转北京时间展示串：2026-11-08 20:34:56 (UTC+8)
// 解析失败时原样返回并加 " (raw)" 标注——不伪造时间。
std::string beijing_time_str(const std::string& utc_iso);

// prefix-<32 位十六进制随机 id>（std::random_device）
std::string random_id(const std::string& prefix);

std::string to_lower(std::string s);
bool contains_ci(const std::string& hay, const std::string& needle); // 仅 ASCII 大小写不敏感
bool starts_with(const std::string& s, const std::string& p);
bool ends_with(const std::string& s, const std::string& p);
std::string trim(const std::string& s);
std::vector<std::string> split_lines(const std::string& s);
std::string join(const std::vector<std::string>& v, const std::string& sep);

// 严格的 UTF-8 序列校验（用于编码探测；非校验位必须正确）
bool is_valid_utf8(const std::string& s);

// HTML 转义（&<>"'）——报告输出强制使用
std::string escape_html(const std::string& s);

// 非 UTF-8 字节清洗：无效序列替换为 \xNN 转义（可读且 JSON 安全）。
// 一切进入 Evidence/Finding 字符串字段的外部文本必须先过此函数。
std::string sanitize_utf8(const std::string& s);

// 标准 base64 解码（容忍空白/填充缺失）；失败返回 false。
bool base64_decode(const std::string& in, std::string& out);

} // namespace ctfir
