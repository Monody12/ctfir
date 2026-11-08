// 平台与核心补充单测（v0.3 自评循环 R2：15 → 25+）
#include "test_macros.hpp"

#include "core/util.hpp"

#if defined(_WIN32)
#include "platform/win/win_common.hpp"
#endif

#include <string>
#include <vector>

using namespace ctfir;

#if defined(_WIN32)
using namespace ctfir::win;

CTFIR_TEST(extract_paths_nested_quotes) {
    // A7C9-W03 实际形态：cmd /c ""C:\CTF-Test\x\harmless.cmd""
    auto v = extract_paths("C:\\Windows\\System32\\cmd.exe /d /c \"\"C:\\CTF-Test\\x\\harmless.cmd\"\"");
    bool found = false;
    for (const auto& p : v)
        if (p.find("harmless.cmd") != std::string::npos) found = true;
    CHECK(found);
}

CTFIR_TEST(extract_paths_bare_and_quoted) {
    auto v = extract_paths("\"C:\\Program Files\\App\\a.exe\" -conf C:\\Temp\\x.ini");
    bool q = false, b = false;
    for (const auto& p : v) {
        if (p.find("a.exe") != std::string::npos) q = true;
        if (p.find("x.ini") != std::string::npos) b = true;
    }
    CHECK(q);
    CHECK(b);
}

CTFIR_TEST(extract_paths_no_path) {
    auto v = extract_paths("powershell.exe -nop -w hidden -enc ABCD");
    // 无反斜杠路径 → 不应误提取 "-enc" 等参数
    bool has_flag = false;
    for (const auto& p : v)
        if (p == "-enc" || p == "ABCD") has_flag = true;
    CHECK(!has_flag);
}

CTFIR_TEST(extract_paths_relative_backslash_seg) {
    auto v = extract_paths("cmd /c \"\\dir\\x.cmd\"");
    CHECK(!v.empty());
}
#endif

CTFIR_TEST(base64_decode_vectors) {
    std::string out;
    CHECK(base64_decode("aGVsbG8=", out));
    CHECK_EQ(out, std::string("hello"));
    CHECK(base64_decode(std::string("QQ=="), out));
    CHECK_EQ(out, std::string("A"));
    CHECK(!base64_decode("!!!", out));   // 非法字符
    CHECK(base64_decode("", out));
    CHECK(out.empty());
    // SSH key blob 场景（长串含空白换行）
    CHECK(base64_decode("aGVs\nbG8=", out));
    CHECK_EQ(out, std::string("hello"));
}

CTFIR_TEST(split_lines_crlf_and_edges) {
    auto v = split_lines("a\r\nb\nc\r\n");
    CHECK_EQ(v.size(), static_cast<size_t>(3));
    CHECK_EQ(v[0], std::string("a"));
    CHECK_EQ(v[1], std::string("b"));
    CHECK_EQ(v[2], std::string("c"));
    auto e = split_lines("");
    CHECK_EQ(e.size(), static_cast<size_t>(1));
}

CTFIR_TEST(utf8_edges) {
    CHECK(is_valid_utf8(""));
    CHECK(is_valid_utf8("中文\xf0\x9f\x98\x80")); // 4 字节 emoji
    CHECK(!is_valid_utf8("\xed\xa0\x80"));        // 代理区拒绝
    CHECK(!is_valid_utf8("\xc0\x80"));            // 过长编码拒绝
    // 清洗不丢合法段
    std::string mixed = "ok\xe4\xb8\xad" "\xff" "tail";
    std::string out = sanitize_utf8(mixed);
    CHECK(is_valid_utf8(out));
    CHECK(out.find("中") != std::string::npos);
    CHECK(out.find("tail") != std::string::npos);
}
