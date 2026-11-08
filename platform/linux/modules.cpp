// Linux 模块注册聚合
#include "lnx_common.hpp"

namespace ctfir::lnx {
void register_mods_a(std::vector<Session::ModuleDef>& mods);
void register_mods_b(std::vector<Session::ModuleDef>& mods);
} // namespace ctfir::lnx

namespace ctfir {

std::vector<Session::ModuleDef> build_platform_modules() {
    std::vector<Session::ModuleDef> mods;
    ctfir::lnx::register_mods_a(mods);
    ctfir::lnx::register_mods_b(mods);
    return mods;
}

} // namespace ctfir
