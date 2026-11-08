// Windows 宿主信息探测（只读）
#include "platform/modules_registry.hpp"
#include <windows.h>
#include <string>

namespace ctfir {

static std::string reg_sz(HKEY root, const wchar_t* sub, const wchar_t* val) {
    HKEY h;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return "";
    wchar_t buf[512]{};
    DWORD size = sizeof(buf), type = 0;
    LSTATUS st = RegQueryValueExW(h, val, nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(h);
    if (st != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return "";
    int need = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    std::string out(need > 0 ? need - 1 : 0, 0);
    if (need > 0) WideCharToMultiByte(CP_UTF8, 0, buf, -1, out.data(), need, nullptr, nullptr);
    return out;
}

std::string detect_os_name() {
    std::string pn = reg_sz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");
    return pn.empty() ? "Windows NT" : pn;
}

std::string detect_os_version() {
    // CurrentVersion 6.1 + CurrentBuildNumber + CSDVersion(SP)
    std::string cv = reg_sz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentVersion");
    std::string cb = reg_sz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
    std::string sp = reg_sz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CSDVersion");
    std::string v = cv + "." + (cb.empty() ? "?" : cb);
    if (!sp.empty()) v += " " + sp;
    return v;
}

std::string detect_os_arch() {
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    return si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64"
         : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86" : "unknown";
}

std::string detect_privilege() {
    BOOL elevated = FALSE;
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION el{};
        DWORD ret = 0;
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &ret))
            elevated = el.TokenIsElevated;
        CloseHandle(tok);
    }
    return elevated ? "admin" : "user";
}

} // namespace ctfir
