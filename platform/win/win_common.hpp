#pragma once
// Windows 平台共享助手（platform/win 内部使用）
// 纪律：注册表全部 KEY_WOW64_64KEY 视图为默认（x64 真实视图），另显式标注 32 位视图来源；
//       宽字符一律 UTF-8 转换；只读 API；错误码留痕。
#include "core/session.hpp"
#include "core/evidence.hpp"
#include "core/util.hpp"

#include <windows.h>
#include <lm.h>
#include <shlobj.h>
#include <sstream>
#include <string>
#include <vector>

// windows.h 的 ERROR 宏与 ModuleStatus::ERROR 冲突；本库不使用该宏
#undef ERROR

namespace ctfir::win {

inline std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int need = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                   nullptr, 0, nullptr, nullptr);
    std::string out(need > 0 ? need : 0, 0);
    if (need > 0)
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                            out.data(), need, nullptr, nullptr);
    return out;
}

inline std::wstring utf8_to_wide(const std::string& u8) {
    if (u8.empty()) return L"";
    int need = MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), static_cast<int>(u8.size()), nullptr, 0);
    std::wstring out(need > 0 ? need : 0, 0);
    if (need > 0)
        MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), static_cast<int>(u8.size()), out.data(), need);
    return out;
}

inline std::string last_error_str(const char* api) {
    DWORD e = GetLastError();
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s err=%lu", api, static_cast<unsigned long>(e));
    return buf;
}

// ---- 注册表 ----
struct RegValue {
    std::string name;
    std::string type;    // REG_SZ / DWORD / EXPAND_SZ / ...
    std::string data;    // 字符串化（DWORD 十进制）
};

// 打开注册表键（64 位视图为默认；view32=true 时走 WOW64_32 并由调用方标注）
inline HKEY open_key(HKEY root, const std::wstring& sub, bool view32, REGSAM extra = 0) {
    HKEY h = nullptr;
    REGSAM sam = KEY_READ | (view32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY) | extra;
    if (RegOpenKeyExW(root, sub.c_str(), 0, sam, &h) != ERROR_SUCCESS) return nullptr;
    return h;
}

inline std::vector<RegValue> reg_values(HKEY h) {
    std::vector<RegValue> out;
    DWORD idx = 0;
    wchar_t name[512]{};
    DWORD name_len = 512;
    for (;;) {
        name_len = 512;
        DWORD type = 0, size = 0;
        LONG st = RegEnumValueW(h, idx++, name, &name_len, nullptr, &type, nullptr, &size);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st != ERROR_SUCCESS) break;
        std::string data;
        if (size > 0 && size < 1024 * 1024) {
            std::vector<BYTE> buf(size);
            DWORD t2 = 0, s2 = size;
            if (RegQueryValueExW(h, name, nullptr, &t2, buf.data(), &s2) == ERROR_SUCCESS) {
                if ((t2 == REG_SZ || t2 == REG_EXPAND_SZ) && s2 >= 2)
                    data = wide_to_utf8(std::wstring(reinterpret_cast<wchar_t*>(buf.data()), s2 / 2));
                else if (t2 == REG_DWORD && s2 >= 4) {
                    DWORD v = *reinterpret_cast<DWORD*>(buf.data());
                    data = std::to_string(v);
                } else {
                    data = "<binary " + std::to_string(s2) + "B>";
                }
            }
        }
        const char* tn = type == REG_SZ ? "REG_SZ" : type == REG_EXPAND_SZ ? "REG_EXPAND_SZ"
                        : type == REG_DWORD ? "REG_DWORD" : type == REG_BINARY ? "REG_BINARY"
                        : type == REG_MULTI_SZ ? "REG_MULTI_SZ" : "OTHER";
        out.push_back({wide_to_utf8(name), tn, data});
    }
    return out;
}

inline std::vector<std::wstring> reg_subkeys(HKEY h) {
    std::vector<std::wstring> out;
    DWORD idx = 0;
    wchar_t name[512]{};
    DWORD name_len = 512;
    for (;;) {
        name_len = 512;
        LONG st = RegEnumKeyExW(h, idx++, name, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st != ERROR_SUCCESS) break;
        out.push_back(name);
    }
    return out;
}

// 读单个值（字符串化）
inline bool reg_get(HKEY root, const std::wstring& sub, const wchar_t* value,
                    bool view32, std::string& out) {
    HKEY h = open_key(root, sub, view32);
    if (!h) return false;
    wchar_t buf[1024]{};
    DWORD size = sizeof(buf), type = 0;
    LONG st = RegQueryValueExW(h, value, nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(h);
    if (st != ERROR_SUCCESS) return false;
    if ((type == REG_SZ || type == REG_EXPAND_SZ) && size >= 2) {
        out = wide_to_utf8(std::wstring(reinterpret_cast<wchar_t*>(buf), size / 2));
    } else if (type == REG_DWORD && size >= 4) {
        out = std::to_string(*reinterpret_cast<DWORD*>(buf));
    } else {
        out = "<binary>";
    }
    return true;
}

// ---- 判定助手 ----
// 可疑启动路径判定：非系统/Program Files 目录
inline bool is_writable_path(const std::string& path_utf8) {
    std::string p = to_lower(path_utf8);
    for (const char* bad : {"\\temp\\", "\\tmp\\", "\\users\\", "\\programdata\\",
                            "\\windows\\tracing\\", "\\recycler\\", "\\public\\"})
        if (p.find(bad) != std::string::npos) return true;
    return false;
}

inline bool is_expected_path(const std::string& path_utf8) {
    std::string p = to_lower(path_utf8);
    for (const char* ok : {"\\windows\\system32", "\\windows\\syswow64",
                           "\\program files", "\\windows\\explorer.exe"})
        if (p.find(ok) != std::string::npos) return true;
    return false;
}

inline std::string sysroot() {
    char buf[MAX_PATH]{};
    GetWindowsDirectoryA(buf, MAX_PATH);
    return buf;
}

inline bool file_exists(const std::string& p) {
    DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

inline bool dir_exists(const std::string& p) {
    DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

// 行遍历（带行号回调）
template <typename F>
inline void for_each_line(const std::string& content, F cb) {
    auto lines = split_lines(content);
    for (size_t i = 0; i < lines.size(); ++i) cb(static_cast<int>(i + 1), lines[i]);
}

// 从命令行文本提取引用的 Windows 路径（引号段优先 + X:\ 起点扫描；无正则）。
// 覆盖 A7C9-W03 类形态：cmd /c ""C:\dir\x.cmd""（嵌套引号）、参数裸路径。
inline std::vector<std::string> extract_paths(const std::string& cmdline_utf8) {
    std::vector<std::string> out;
    const std::string& s = cmdline_utf8;
    size_t i = 0, n = s.size();
    while (i < n) {
        char c = s[i];
        if (c == '"') {
            // 引号段：整段当候选路径（可能含参数，再细分）
            size_t j = i + 1;
            std::string seg;
            while (j < n && s[j] != '"') { seg += s[j]; ++j; }
            // 引号段内再扫 X:\ 起点
            for (const auto& p : extract_paths(seg)) out.push_back(p);
            if (!seg.empty() && seg.find(':') == std::string::npos && seg.find('\\') != std::string::npos)
                out.push_back(seg); // 相对形式如 \dir\x
            i = (j < n) ? j + 1 : n;
            continue;
        }
        // 裸路径：字母 + ':' + '\' 起点
        if (((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) && i + 2 < n &&
            s[i + 1] == ':' && (s[i + 2] == '\\' || s[i + 2] == '/')) {
            size_t j = i;
            std::string path;
            while (j < n && s[j] != ' ' && s[j] != '"' && s[j] != ',') { path += s[j]; ++j; }
            out.push_back(path);
            i = j;
            continue;
        }
        // 反斜杠开头的绝对形式 \dir\x（跟随在引号内已处理；此处跳过）
        ++i;
    }
    return out;
}

// 读文件证据（宽路径已在 core/evidence 处理 UTF-8 → 直接用）
inline ReadResult read_file(ModuleCtx& ctx, const std::string& path, size_t cap = 4 * 1024 * 1024) {
    ctx.planned_source(path);
    ReadResult r = read_text_file(path, cap);
    if (r.ok) {
        Evidence e;
        e.source_kind = "file";
        e.source_path = path;
        e.sha256 = r.raw_sha256;
        e.access_status = r.access_status;
        e.payload = r.content.size() > 64 * 1024
                        ? r.content.substr(0, 64 * 1024) + "\n...[截断展示]"
                        : r.content;
        ctx.add_evidence(e);
        ctx.checked_source(path);
    } else if (r.access_status == "not_found") {
        ctx.checked_source(path + " [not_found]");
    } else {
        ctx.omitted_source(path, r.access_status);
    }
    return r;
}

} // namespace ctfir::win
