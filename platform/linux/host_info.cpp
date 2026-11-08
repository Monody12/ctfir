// Linux 宿主信息探测（只读，本地文件/系统调用）
#include "platform/modules_registry.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sys/utsname.h>
#include <unistd.h>

namespace ctfir {

static std::string os_release_field(const char* key) {
    std::ifstream f("/etc/os-release");
    if (!f) return "";
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind(key, 0) == 0) {
            std::string v = line.substr(strlen(key));
            if (!v.empty() && v[0] == '=') v = v.substr(1);
            if (v.size() >= 2 && v.front() == '"') v = v.substr(1, v.size() - 2);
            return v;
        }
    }
    return "";
}

std::string detect_os_name() {
    std::string pretty = os_release_field("PRETTY_NAME=");
    if (!pretty.empty()) return pretty;
    return os_release_field("NAME=");
}

std::string detect_os_version() {
    utsname u{};
    if (uname(&u) != 0) return "";
    return u.release;
}

std::string detect_os_arch() {
    utsname u{};
    if (uname(&u) != 0) return "unknown";
    return u.machine; // x86_64
}

std::string detect_privilege() {
    return geteuid() == 0 ? "root" : "user";
}

} // namespace ctfir
