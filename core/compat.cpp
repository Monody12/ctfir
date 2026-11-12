#include "compat.hpp"
#include "platform/modules_registry.hpp"

namespace ctfir {

static int win_build_number(const std::string& os_arch, const std::string& os_version) {
    // Windows detect_os_arch 是 x64/x86；Linux 是 x86_64/i686，避免把内核 6.6.87 当成 build。
    if (os_arch != "x64" && os_arch != "x86") return 0;
    std::string v = os_version;
    size_t sp = v.find(' ');
    if (sp != std::string::npos) v = v.substr(0, sp);
    int dots = 0, acc = 0;
    bool digit = false;
    for (char c : v) {
        if (c >= '0' && c <= '9') {
            acc = acc * 10 + (c - '0');
            digit = true;
        } else if (c == '.') {
            acc = 0;
            ++dots;
            digit = false;
        } else {
            return 0;
        }
    }
    if (dots >= 2 && digit) return acc;
    return 0;
}

HostCompat evaluate_host_compat_from(const std::string& /*os_name*/,
                                     const std::string& os_version,
                                     const std::string& os_arch,
                                     const char* bin_arch) {
    HostCompat h;
    h.binary_arch = bin_arch ? bin_arch : "unknown";
    h.level = "ok";
    h.note.clear();

    const std::string& ba = h.binary_arch;
    if (ba == "x64" && (os_arch == "x86" || os_arch == "i686" || os_arch == "i386")) {
        h.level = "warn";
        h.note = "本包是 64 位 PE，无法在 32 位 Windows 上启动。32 位赛机需要单独的 x86 包（本仓库按 ADR-001 未交付）。";
        return h;
    }
    if (ba == "x86" && (os_arch == "x64" || os_arch == "AMD64" || os_arch == "x86_64")) {
        h.level = "warn";
        h.note = "32 位进程跑在 64 位 Windows 上会受 WOW64 重定向，IR 扫描不完整。请用 windows-x64 包。";
        return h;
    }
    if ((ba == "x86_64") && (os_arch == "i686" || os_arch == "i386")) {
        h.level = "warn";
        h.note = "本包是 x86_64 静态二进制，无法在 32 位 Linux 上运行。";
        return h;
    }

    int build = win_build_number(os_arch, os_version);
    if (build > 0 && build < 7601) {
        h.level = "warn";
        h.note = "Windows build " + std::to_string(build) +
                 " 未验证（Win7 RTM=7600）。主线最低 Win7 SP1 / Server 2008 R2 SP1（7601）。"
                 "扫描可能不完整；若程序无法启动，用 winver / systeminfo 确认已打 SP1。";
        return h;
    }
    return h;
}

HostCompat evaluate_host_compat() {
    return evaluate_host_compat_from(detect_os_name(), detect_os_version(),
                                     detect_os_arch(), binary_arch());
}

} // namespace ctfir
