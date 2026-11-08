// Windows 采集模块注册（WP4 填充；当前空表保证工程可构建）
#include "platform/modules_registry.hpp"

namespace ctfir {
std::vector<Session::ModuleDef> build_platform_modules() {
    std::vector<Session::ModuleDef> mods;
    // W01..W13 在 WP4 注册于此
    return mods;
}
} // namespace ctfir
