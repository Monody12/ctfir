// Linux v0.5-R6 遗漏补齐：进程从 /tmp//dev/shm 运行、XDG Autostart、
// Python startup hooks、bashrc 函数后门、Udev Rules、MySQL socket 弱口令
#include "lnx_common.hpp"

#include <cstring>
#include <set>

namespace ctfir::lnx {

namespace {

// ---- 进程从临时目录运行（CTF IR 高频考点！）----
void mod_tmp_proc(ModuleCtx& ctx) {
    for (const auto& p : list_dir("/proc", 20000)) {
        std::string base = p.substr(p.find_last_of('/') + 1);
        if (base.empty() || base[0] < '0' || base[0] > '9') continue;
        if (ctx.expired()) { ctx.note("预算截断"); break; }
        char buf[1024]{};
        ssize_t n = readlink((p + "/exe").c_str(), buf, sizeof(buf) - 1);
        if (n <= 0) continue;
        std::string exe(buf, static_cast<size_t>(n));
        std::string low = to_lower(exe);
        // exe 路径在临时/可写目录
        if (low.find("/tmp/") != std::string::npos || low.find("/dev/shm/") != std::string::npos ||
            low.find("/var/tmp/") != std::string::npos) {
            Finding f;
            f.rule_id = "LNX.PROC.TMPDIR.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "进程从临时目录运行: PID " + base + " → " + exe +
                          "（恶意程序常见落点；编译器/包管理器属正常场景需排除）";
            f.object_ref = "PID " + base;
            f.evidence_paths = {exe};
            f.advice_id = "ADVICE.MINER.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- XDG Autostart（Linux 桌面自启动）----
void mod_xdg(ModuleCtx& ctx) {
    std::vector<std::string> dirs = {"/etc/xdg/autostart"};
    // 用户级
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    if (pw.ok) {
        for_each_line(pw.content, [&](int, const std::string& line) {
            int seen = 0, p5 = 0, p6 = 0;
            for (int i = 0; i < (int)line.size(); ++i) {
                if (line[i] == ':') { ++seen; if (seen == 5) p5 = i; if (seen == 6) { p6 = i; break; } }
            }
            if (seen < 6) return;
            std::string home = line.substr(p5 + 1, p6 - p5 - 1);
            if (home[0] == '/') dirs.push_back(home + "/.config/autostart");
        });
    }
    for (const auto& d : dirs) {
        for (const auto& f : list_dir(d, 100)) {
            if (!ends_with(f, ".desktop")) continue;
            ReadResult r = read_source(ctx, f, false);
            if (!r.ok) continue;
            for_each_line(r.content, [&](int no, const std::string& line) {
                std::string t = trim(line);
                if (!starts_with(t, "Exec=")) return;
                std::string cmd = t.substr(5);
                auto hits = match_tokens(cmd);
                bool writable = cmd.find("/tmp/") != std::string::npos ||
                                cmd.find("/dev/shm") != std::string::npos;
                if (!hits.empty() || writable) {
                    Finding fd;
                    fd.rule_id = "LNX.PERSIST.XDG.001";
                    fd.severity = writable ? "medium" : "low";
                    fd.confidence = "medium";
                    fd.rationale = "XDG Autostart 自启动项可疑: " + f + " Exec=" + cmd.substr(0, 150);
                    fd.object_ref = f;
                    fd.advice_id = "ADVICE.CRON.REVIEW.001";
                    ctx.add_finding(fd);
                }
            });
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- Python startup hooks（sitecustomize.py / usercustomize.py）----
void mod_pypersist(ModuleCtx& ctx) {
    std::vector<std::string> paths;
    // 常见 Python site-packages 位置
    for (const char* base : {"/usr/lib/python", "/usr/local/lib/python", "/usr/lib/python3", "/usr/local/lib/python3"}) {
        // sitecustomize.py / usercustomize.py 直接放或 site-packages 下
        paths.push_back(std::string(base) + "/sitecustomize.py");
        paths.push_back(std::string(base) + "/usercustomize.py");
        paths.push_back(std::string(base) + "/site-packages/sitecustomize.py");
        paths.push_back(std::string(base) + "/site-packages/usercustomize.py");
    }
    // 版本目录
    for (const auto& d : list_dir("/usr/lib", 50)) {
        if (d.find("python") == std::string::npos) continue;
        paths.push_back(d + "/sitecustomize.py");
        paths.push_back(d + "/site-packages/sitecustomize.py");
    }
    for (const auto& p : paths) {
        ReadResult r = read_source(ctx, p, false);
        if (!r.ok) continue;
        auto hits = match_tokens(r.content);
        bool has_import = contains_ci(r.content, "import os") || contains_ci(r.content, "import subprocess") ||
                          contains_ci(r.content, "exec(") || contains_ci(r.content, "eval(");
        if (!hits.empty() || has_import) {
            Finding f;
            f.rule_id = "LNX.PERSIST.PYHOOK.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "Python 启动钩子含可疑代码: " + p + "（每次 Python 启动时自动执行）";
            f.object_ref = p;
            f.advice_id = "ADVICE.PROFILE.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- bashrc 函数后门（伪造 su/sudo/passwd 等关键命令）----
void mod_bashfunc(ModuleCtx& ctx) {
    std::vector<std::string> files = {"/etc/bash.bashrc", "/etc/bashrc"};
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    if (pw.ok) {
        for_each_line(pw.content, [&](int, const std::string& line) {
            int seen = 0, p5 = 0, p6 = 0;
            for (int i = 0; i < (int)line.size(); ++i) {
                if (line[i] == ':') { ++seen; if (seen == 5) p5 = i; if (seen == 6) { p6 = i; break; } }
            }
            if (seen < 6) return;
            std::string home = line.substr(p5 + 1, p6 - p5 - 1);
            if (home[0] == '/') {
                files.push_back(home + "/.bashrc");
                files.push_back(home + "/.bash_profile");
            }
        });
    }
    for (const auto& f : files) {
        ReadResult r = read_source(ctx, f, false);
        if (!r.ok) continue;
        for_each_line(r.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            // 函数定义覆盖关键命令
            if (starts_with(t, "function su(") || starts_with(t, "su()") ||
                starts_with(t, "function sudo(") || starts_with(t, "sudo()") ||
                starts_with(t, "function passwd(") || starts_with(t, "passwd()") ||
                starts_with(t, "function login(") || starts_with(t, "login()")) {
                Finding fd;
                fd.rule_id = "LNX.PERSIST.BASHFUNC.001";
                fd.severity = "high";
                fd.confidence = "medium";
                fd.rationale = "shell 配置定义了关键命令的同名函数（函数后门——可窃取口令后转发真实命令）: " +
                               t.substr(0, 120) + "（" + f + " 第 " + std::to_string(no) + " 行）";
                fd.object_ref = f + ":" + std::to_string(no);
                fd.advice_id = "ADVICE.PROFILE.REVIEW.001";
                ctx.add_finding(fd);
            }
        });
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- Udev Rules（T1546.017）----
void mod_udev(ModuleCtx& ctx) {
    for (const char* d : {"/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d"}) {
        for (const auto& f : list_dir(d, 100)) {
            ReadResult r = read_source(ctx, f, false);
            if (!r.ok) continue;
            for_each_line(r.content, [&](int no, const std::string& line) {
                std::string t = trim(line);
                if (t.empty() || t[0] == '#') return;
                if (contains_ci(t, "RUN+") || contains_ci(t, "RUN=")) {
                    // 提取 RUN 后面的命令
                    size_t run_pos = to_lower(t).find("run+=");
                    if (run_pos == std::string::npos) run_pos = to_lower(t).find("run=");
                    if (run_pos == std::string::npos) return;
                    std::string cmd = t.substr(run_pos + 4);
                    auto hits = match_tokens(cmd);
                    bool writable = cmd.find("/tmp/") != std::string::npos ||
                                    cmd.find("/dev/shm") != std::string::npos;
                    if (!hits.empty() || writable) {
                        Finding fd;
                        fd.rule_id = "LNX.PERSIST.UDEV.001";
                        fd.severity = "high";
                        fd.confidence = "medium";
                        fd.rationale = "Udev 规则含可疑 RUN 命令（设备插入时自动执行）: " + cmd.substr(0, 150);
                        fd.object_ref = f + ":" + std::to_string(no);
                        fd.advice_id = "ADVICE.CRON.REVIEW.001";
                        ctx.add_finding(fd);
                    }
                }
            });
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- MySQL socket 空口令探测（只读）----
void mod_mysql_socket(ModuleCtx& ctx) {
    // 检查 mysql.sock 是否存在 + 配置文件无 requirepass（已在 MID.MYSQL 覆盖配置面）
    // 这里只做文件存在性确认
    if (file_exists("/var/lib/mysql/mysql.sock") || file_exists("/tmp/mysql.sock")) {
        ctx.note("MySQL socket 文件存在——弱口令尝试需 mysql 客户端（工具不执行连接测试）");
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.RANSOM：勒索软件痕迹（玄机/应急响应高频）----
void mod_ransom(ModuleCtx& ctx) {
    // 勒索信文件名模式 + 加密扩展名
    static const char* note_names[] = {
        "readme", "decrypt", "ransom", "restore", "recover", "how_to", "help_",
    };
    static const char* enc_exts[] = {
        ".locked", ".encrypted", ".crypt", ".enc", ".wcry", ".onion",
        ".cerber", ".locky", ".crypto", ".enciphered", ".everbe", ".paymen",
    };
    static const char* roots[] = {
        "/root", "/home", "/tmp", "/var/www/html", "/var/www", "/srv",
    };
    int hits = 0;
    for (const char* root : roots) {
        for (const auto& p : list_dir(root, 600)) {
            if (ctx.expired()) break;
            struct stat st{};
            if (lstat(p.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
            std::string base = to_lower(p.substr(p.find_last_of('/') + 1));
            bool is_note = false;
            for (const char* kw : note_names)
                if (base.find(kw) != std::string::npos &&
                    (ends_with(base, ".txt") || ends_with(base, ".html") ||
                     ends_with(base, ".hta") || ends_with(base, ".url"))) {
                    is_note = true; break;
                }
            bool is_enc = false;
            for (const char* ext : enc_exts)
                if (ends_with(base, ext)) { is_enc = true; break; }
            if (!is_note && !is_enc) continue;
            if (base.find("ctfir-marker") != std::string::npos) continue;
            ++hits;
            if (hits <= 10) {
                Finding f;
                f.rule_id = "LNX.RANSOM.TRACE.001";
                f.severity = "high";
                f.confidence = "low";
                f.rationale = std::string("勒索软件痕迹（") + (is_note ? "勒索信" : "加密扩展名") + "）: " +
                              p + "——需人工核实内容；已知备份文件误报可能";
                f.object_ref = p;
                f.advice_id = "ADVICE.HASH.BASELINE.001";
                ctx.add_finding(f);
            }
        }
    }
    // /tmp 下勒索脚本线索
    for (const auto& p : list_dir("/tmp", 400)) {
        ReadResult r = read_text_file(p, 64 * 1024);
        if (!r.ok) continue;
        if (contains_ci(r.content, "openssl enc") || contains_ci(r.content, "gpg --batch") ||
            contains_ci(r.content, "--decrypt-files") || contains_ci(r.content, "shred -u")) {
            Finding f;
            f.rule_id = "LNX.RANSOM.SCRIPT.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "疑似加密脚本（openssl enc/gpg --batch/shred）: " + p.substr(0, 160) +
                          "——勒索软件加密器常见特征";
            f.object_ref = p;
            f.advice_id = "ADVICE.MINER.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    ctx.note("勒索痕迹扫描：勒索信文件名 + 12 种加密扩展名 + /tmp 加密脚本特征；置信度 low 需人工核实");
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_h(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.PROC.TMPDIR", "1.0.0", "linux", [](ModuleCtx& c) { mod_tmp_proc(c); }});
    mods.push_back({"LNX.PERSIST.XDG", "1.0.0", "linux", [](ModuleCtx& c) { mod_xdg(c); }});
    mods.push_back({"LNX.PERSIST.PYHOOK", "1.0.0", "linux", [](ModuleCtx& c) { mod_pypersist(c); }});
    mods.push_back({"LNX.PERSIST.BASHFUNC", "1.0.0", "linux", [](ModuleCtx& c) { mod_bashfunc(c); }});
    mods.push_back({"LNX.PERSIST.UDEV", "1.0.0", "linux", [](ModuleCtx& c) { mod_udev(c); }});
    mods.push_back({"LNX.MYSQL.SOCK", "1.0.0", "linux", [](ModuleCtx& c) { mod_mysql_socket(c); }});
    mods.push_back({"LNX.RANSOM", "1.0.0", "linux", [](ModuleCtx& c) { mod_ransom(c); }});
}

} // namespace ctfir::lnx
