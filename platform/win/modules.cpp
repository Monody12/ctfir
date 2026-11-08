// Windows 模块注册聚合
#include "win_common.hpp"

namespace ctfir::win {
void register_mods_w1(std::vector<Session::ModuleDef>& mods);
void register_mods_w2(std::vector<Session::ModuleDef>& mods);
void register_mods_w3(std::vector<Session::ModuleDef>& mods);
} // namespace ctfir::win

namespace ctfir {

std::vector<Session::ModuleDef> build_platform_modules() {
    std::vector<Session::ModuleDef> mods;
    ctfir::win::register_mods_w1(mods);
    ctfir::win::register_mods_w2(mods);
    ctfir::win::register_mods_w3(mods);
    return mods;
}

} // namespace ctfir
