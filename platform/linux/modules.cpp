// Linux 模块注册聚合
#include "lnx_common.hpp"

namespace ctfir::lnx {
void register_mods_a(std::vector<Session::ModuleDef>& mods);
void register_mods_b(std::vector<Session::ModuleDef>& mods);
void register_mods_c(std::vector<Session::ModuleDef>& mods);
void register_mods_d(std::vector<Session::ModuleDef>& mods);
void register_mods_e(std::vector<Session::ModuleDef>& mods);
void register_mods_f(std::vector<Session::ModuleDef>& mods);
void register_mods_g(std::vector<Session::ModuleDef>& mods);
void register_mods_h(std::vector<Session::ModuleDef>& mods);
} // namespace ctfir::lnx

namespace ctfir {

std::vector<Session::ModuleDef> build_platform_modules() {
    std::vector<Session::ModuleDef> mods;
    ctfir::lnx::register_mods_a(mods);
    ctfir::lnx::register_mods_b(mods);
    ctfir::lnx::register_mods_c(mods);
    ctfir::lnx::register_mods_d(mods);
    ctfir::lnx::register_mods_e(mods);
    ctfir::lnx::register_mods_f(mods);
    ctfir::lnx::register_mods_g(mods);
    ctfir::lnx::register_mods_h(mods);
    return mods;
}

} // namespace ctfir
