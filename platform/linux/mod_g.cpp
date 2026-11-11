// Linux 遗漏检测点补齐（v0.5-迭代R2）：信任主机 / root PATH / GRUB 密码 /
// Ctrl+Alt+Del / core dump limits / 历史命令设置 / NFS / webshell 深化特征
#include "lnx_common.hpp"

#include <cstring>
#include <filesystem>
#include <set>

namespace fs = std::filesystem;

namespace ctfir::lnx {

namespace {

// ---- 信任主机（hosts.equiv / .rhosts）----
void mod_trust(ModuleCtx& ctx) {
    ctx.planned_source("/etc/hosts.equiv");
    ReadResult r = read_text_file("/etc/hosts.equiv", 64 * 1024);
    bool has_equiv = r.ok && !trim(r.content).empty();
    if (has_equiv) {
        Finding f;
        f.rule_id = "LNX.BASE.TRUST.EQUIV.001";
        f.severity = "medium";
        f.confidence = "high";
        f.rationale = "/etc/hosts.equiv 非空（r 系列信任登录：远程主机无需口令即可登录本机）";
        f.object_ref = "/etc/hosts.equiv";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }
    ctx.checked_source("/etc/hosts.equiv");
    // 各用户 .rhosts
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    if (pw.ok) {
        for_each_line(pw.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            int seen = 0, p5 = 0, p6 = 0;
            for (int i = 0; i < (int)t.size(); ++i) {
                if (t[i] == ':') { ++seen; if (seen == 5) p5 = i; if (seen == 6) { p6 = i; break; } }
            }
            if (seen < 6) return;
            std::string home = t.substr(p5 + 1, p6 - p5 - 1);
            std::string name = t.substr(0, t.find(':'));
            if (home.empty() || home[0] != '/') return;
            std::string rh = home + "/.rhosts";
            ReadResult rr = read_text_file(rh, 64 * 1024);
            if (rr.ok && !trim(rr.content).empty()) {
                Finding f;
                f.rule_id = "LNX.BASE.TRUST.RHOSTS.001";
                f.severity = "medium";
                f.confidence = "high";
                f.rationale = "用户 " + name + " 存在非空 .rhosts（信任登录后门常见藏匿点）";
                f.object_ref = rh;
                f.advice_id = "ADVICE.HARDEN.001";
                ctx.add_finding(f);
            }
        });
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- root PATH 含 . / 关键文件权限 ----
void mod_rootpath(ModuleCtx& ctx) {
    // root 的 PATH 从 /root/.bash_profile 或 /etc/profile 提取（静态检查）
    for (const char* pf : {"/root/.bash_profile", "/root/.profile", "/etc/profile"}) {
        ReadResult r = read_text_file(pf, 256 * 1024);
        if (!r.ok) continue;
        for_each_line(r.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (!starts_with(t, "PATH=")) return;
            std::string val = t.substr(5);
            std::istringstream is(val);
            std::string comp;
            while (std::getline(is, comp, ':')) {
                if (comp == ".") {
                    Finding f;
                    f.rule_id = "LNX.BASE.ROOTPATH.001";
                    f.severity = "medium";
                    f.confidence = "high";
                    f.rationale = "PATH 包含当前目录 '.'（" + std::string(pf) + " 第 " + std::to_string(no) +
                                  " 行）——root 可能执行到伪装的特洛伊程序";
                    f.object_ref = std::string(pf) + ":" + std::to_string(no);
                    f.advice_id = "ADVICE.HARDEN.001";
                    ctx.add_finding(f);
                    return;
                }
            }
        });
    }
    // 关键文件权限
    struct FP { const char* path; unsigned expect_max; const char* desc; };
    static const FP fps[] = {
        {"/etc/passwd", 0666, "passwd"},   // 644 正常，666 可写→high
        {"/etc/shadow", 0640, "shadow"},   // 已有 SHADOWPERM 模块
        {"/etc/crontab", 0644, "crontab"},
        {"/etc/group", 0666, "group"},
    };
    for (const auto& fp : fps) {
        struct stat st{};
        if (stat(fp.path, &st) != 0) continue;
        unsigned mode = st.st_mode & 0777;
        if ((mode & 0002) != 0) { // 其他用户可写
            Finding f;
            f.rule_id = "LNX.BASE.FILEPERM.001";
            f.severity = "high";
            f.confidence = "high";
            f.rationale = std::string("关键文件 ") + fp.path + " 其他用户可写（mode " +
                          std::to_string(mode) + "）——任意用户可篡改";
            f.object_ref = fp.path;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- GRUB 密码 / Ctrl+Alt+Del / core dump limits / 历史命令 ----
void mod_grubctrl(ModuleCtx& ctx) {
    // GRUB 密码（grub.cfg 中是否含 password / set superusers）
    for (const char* gf : {"/boot/grub2/grub.cfg", "/boot/grub/grub.cfg"}) {
        ReadResult r = read_text_file(gf, 1024 * 1024);
        if (!r.ok) continue;
        bool has_pwd = contains_ci(r.content, "password_pbkdf2") || contains_ci(r.content, "set superusers");
        if (!has_pwd) {
            Finding f;
            f.rule_id = "LNX.BASE.GRUBPWD.001";
            f.severity = "low";
            f.confidence = "high";
            f.rationale = std::string("GRUB 未设置启动密码（") + gf +
                          "）——单用户模式可无口令进入 root shell（物理接触场景）";
            f.object_ref = gf;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
        break;
    }
    // Ctrl+Alt+Del：systemd target 是否被 mask
    {
        std::error_code ec;
        fs::path p = fs::u8path("/etc/systemd/system/ctrl-alt-del.target");
        bool masked = fs::is_symlink(fs::symlink_status(p, ec)) &&
                      fs::read_symlink(p, ec) == "/dev/null";
        if (!masked) {
            Finding f;
            f.rule_id = "LNX.BASE.CAD.001";
            f.severity = "low";
            f.confidence = "medium";
            f.rationale = "Ctrl+Alt+Del 重启未禁用（ctrl-alt-del.target 未 mask）——物理接触可强制重启";
            f.object_ref = "ctrl-alt-del.target";
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }
    // core dump limits
    ReadResult lim = read_source(ctx, "/etc/security/limits.conf", false);
    if (lim.ok) {
        bool has_core0 = false;
        for_each_line(lim.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            std::istringstream is(t);
            std::string domain, type, item, val;
            if (is >> domain >> type >> item >> val && item == "core" && val == "0")
                has_core0 = true;
        });
        if (!has_core0) {
            Finding f;
            f.rule_id = "LNX.BASE.COREDUMP.001";
            f.severity = "low";
            f.confidence = "medium";
            f.rationale = "limits.conf 未设置 core=0（core dump 可能泄漏敏感内存内容）";
            f.object_ref = "/etc/security/limits.conf";
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }
    // 历史命令设置
    ReadResult prof = read_source(ctx, "/etc/profile", false);
    if (prof.ok) {
        bool has_hist = contains_ci(prof.content, "HISTSIZE") || contains_ci(prof.content, "HISTFILE");
        if (!has_hist)
            ctx.note("基线提示：/etc/profile 未显式设置 HISTSIZE/HISTTIMEFORMAT（历史命令全量保留且无时间戳）");
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- NFS 服务检查 ----
void mod_nfs(ModuleCtx& ctx) {
    for (const char* p : {"/etc/exports", "/etc/exports.d"}) {
        if (file_exists(p)) {
            ReadResult r = read_source(ctx, p, false);
            if (r.ok && !trim(r.content).empty()) {
                Finding f;
                f.rule_id = "LNX.BASE.NFS.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "NFS 导出配置非空: " + std::string(p) + "——确认导出范围与权限";
                f.object_ref = p;
                f.advice_id = "ADVICE.HARDEN.001";
                ctx.add_finding(f);
            }
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_g(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.BASE.TRUST", "1.0.0", "linux", [](ModuleCtx& c) { mod_trust(c); }});
    mods.push_back({"LNX.BASE.ROOTPATH", "1.0.0", "linux", [](ModuleCtx& c) { mod_rootpath(c); }});
    mods.push_back({"LNX.BASE.GRUB", "1.0.0", "linux", [](ModuleCtx& c) { mod_grubctrl(c); }});
    mods.push_back({"LNX.BASE.NFS", "1.0.0", "linux", [](ModuleCtx& c) { mod_nfs(c); }});
}

} // namespace ctfir::lnx
