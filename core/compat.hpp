#pragma once
// 宿主兼容性提示：不阻断扫描，只警告未验证格。
// 主线：Win7 SP1 / Server 2008 R2 SP1 x64（build ≥ 7601）+ Linux x86_64。
#include <string>

namespace ctfir {

#if defined(_WIN64)
inline const char* binary_arch() { return "x64"; }
#elif defined(_WIN32)
inline const char* binary_arch() { return "x86"; }
#elif defined(__x86_64__) || defined(__amd64__)
inline const char* binary_arch() { return "x86_64"; }
#elif defined(__i386__)
inline const char* binary_arch() { return "i686"; }
#else
inline const char* binary_arch() { return "unknown"; }
#endif

struct HostCompat {
    std::string binary_arch;
    std::string level;  // "ok" | "warn"
    std::string note;   // UTF-8；ok 时为空
};

// 读 detect_os_*()。
HostCompat evaluate_host_compat();

// 单测用：不碰真实系统。
HostCompat evaluate_host_compat_from(const std::string& os_name,
                                     const std::string& os_version,
                                     const std::string& os_arch,
                                     const char* bin_arch);

} // namespace ctfir
