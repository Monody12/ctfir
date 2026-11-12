#pragma once
// 平台模块注册表：build_platform_modules() 返回本平台全部采集模块。
#include "core/session.hpp"
#include <vector>

namespace ctfir {
std::vector<Session::ModuleDef> build_platform_modules();
std::string detect_os_name();     // 如 "Windows 7" / "CentOS 7"
std::string detect_os_version();  // 如 "6.1.7601 SP1" / "3.10.0-1160"
std::string detect_os_arch();     // x64 / x86 / x86_64
std::string detect_privilege();   // "admin" / "user" / "root"
std::string detect_product_type(); // Windows: WinNT/ServerNT/LanmanNT；Linux 空
}
