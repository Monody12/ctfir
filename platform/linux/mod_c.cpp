// Linux 扩容模块（v0.3 Phase0-C）：capabilities / at 队列 / shadow 权限 / systemd timers 事实化
#include "lnx_common.hpp"

#include <sys/stat.h>
#include <sys/xattr.h>
#include <cstring>
#include <set>

namespace ctfir::lnx {

namespace {

// ---- LNX.CAPS：文件 capabilities ----
void mod_caps(ModuleCtx& ctx) {
    const char* dirs[] = {"/usr/bin", "/usr/sbin", "/bin", "/sbin"};
    const char* known[] = {"ping", "mtr-packet", "traceroute6.iputils"};
    std::set<std::string> allow(known, known + sizeof(known) / sizeof(known[0]));
    int found = 0;
    for (const char* d : dirs) {
        for (const auto& p : list_dir(d, 5000)) {
            if (ctx.expired()) { ctx.note("预算截断"); goto done; }
            unsigned char buf[128];
            ssize_t n = getxattr(p.c_str(), "security.capability", buf, sizeof(buf));
            if (n <= 0) continue;
            std::string name = p.substr(p.find_last_of('/') + 1);
            ++found;
            Evidence e;
            e.source_kind = "file";
            e.source_path = p;
            e.object_identity = "security.capability xattr(" + std::to_string(n) + "B)";
            e.payload = "(capability 元数据留证)";
            ctx.add_evidence(e);
            if (!allow.count(name)) {
                Finding f;
                f.rule_id = "LNX.CAPS.UNEXPECTED.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "非常见文件具备 capabilities: " + p +
                              "（容器/发行版工具可能合法，需人工核对 cap 集）";
                f.object_ref = p;
                f.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    }
done:
    if (found == 0) ctx.note("未发现文件 capabilities（正常）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.AT：at 队列 ----
void mod_at(ModuleCtx& ctx) {
    for (const char* d : {"/var/spool/cron/atjobs", "/var/spool/at", "/var/spool/atjobs"}) {
        for (const auto& p : list_dir(d, 200)) {
            ReadResult r = read_source(ctx, p, false);
            if (!r.ok) continue;
            for_each_line(r.content, [&](int no, const std::string& line) {
                auto hits = match_tokens(line);
                if (hits.empty()) return;
                std::string whys;
                for (auto& [tk, why] : hits) whys += tk + " ";
                Finding f;
                f.rule_id = "LNX.PERSIST.AT.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "at 队列任务含可疑特征: " + whys + "（" + p + " 第 " + std::to_string(no) + " 行）";
                f.object_ref = p + ":" + std::to_string(no);
                f.advice_id = "ADVICE.CRON.REVIEW.001";
                ctx.add_finding(f);
            });
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.SHADOWPERM：shadow 权限异常 ----
void mod_shadowperm(ModuleCtx& ctx) {
    ctx.planned_source("/etc/shadow");
    struct stat st{};
    if (stat("/etc/shadow", &st) != 0) {
        ctx.checked_source("/etc/shadow [not_found]（部分发行版用其他机制）");
        ctx.set_status(ModuleStatus::PASS);
        return;
    }
    bool world_read = (st.st_mode & S_IROTH) != 0;
    bool group_read = (st.st_mode & S_IRGRP) != 0;
    Evidence e;
    e.source_kind = "file";
    e.source_path = "/etc/shadow";
    e.payload = "mode=" + std::to_string((st.st_mode & 07777)) +
                " owner=" + std::to_string(st.st_uid) + ":" + std::to_string(st.st_gid);
    ctx.add_evidence(e);
    ctx.checked_source("/etc/shadow");
    if (world_read) {
        Finding f;
        f.rule_id = "LNX.ACC.SHADOWPERM.001";
        f.severity = "high";
        f.confidence = "high";
        f.rationale = "/etc/shadow 其他用户可读（权限 " + std::to_string((st.st_mode & 07777)) +
                      "）——本机所有用户可离线爆破哈希，属高危配置";
        f.object_ref = "/etc/shadow";
        f.advice_id = "ADVICE.ACC.REVIEW.001";
        ctx.add_finding(f);
    } else if (group_read) {
        Finding f;
        f.rule_id = "LNX.ACC.SHADOWPERM.001";
        f.severity = "low";
        f.confidence = "medium";
        f.rationale = "/etc/shadow 组可读（shadow 组惯例可接受，需核实组成员）";
        f.object_ref = "/etc/shadow";
        f.advice_id = "ADVICE.ACC.REVIEW.001";
        ctx.add_finding(f);
    }
    ctx.note("shadow 内容绝不读取/保存（红线），仅权限元数据");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.TIMERFACT：systemd timers 事实化 ----
void mod_timers(ModuleCtx& ctx) {
    for (const auto& p : list_dir("/etc/systemd/system", 300)) {
        if (!ends_with(p, ".timer")) continue;
        ReadResult r = read_source(ctx, p, false);
        if (!r.ok) continue;
        std::string sched;
        for_each_line(r.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            if (starts_with(t, "OnCalendar") || starts_with(t, "OnUnitActiveSec") ||
                starts_with(t, "OnBootSec"))
                sched += t + " ";
        });
        Finding f;
        f.rule_id = "LNX.TIMER.FACT.001";
        f.severity = "low";
        f.confidence = "high";
        f.rationale = "自定义 systemd timer: " + p + "（调度 " +
                      (sched.empty() ? "未声明" : sched.substr(0, 100)) + "）——事实呈现";
        f.object_ref = p;
        f.advice_id = "ADVICE.CRON.REVIEW.001";
        ctx.add_finding(f);
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.FILES：附加目录巡检（双扩展名 + 基线比对，与 WIN.FILES 对称）----
static bool looks_exec_name_l(const std::string& low) {
    return ends_with(low, ".exe") || ends_with(low, ".scr") || ends_with(low, ".bin") ||
           ends_with(low, ".run") || ends_with(low, ".sh") || ends_with(low, ".elf");
}

static void files_walk(ModuleCtx& ctx, const std::string& dir, int depth, int& files,
                       int& double_ext, int& mismatch, int& miss,
                       std::map<std::string, std::string>& baseline,
                       std::set<std::string>& seen) {
    if (depth > 3 || files > 800 || ctx.expired()) return;
    for (const auto& p : list_dir(dir, 500)) {
        struct stat st{};
        if (lstat(p.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            files_walk(ctx, p, depth + 1, files, double_ext, mismatch, miss, baseline, seen);
            if (files > 800 || ctx.expired()) return;
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        if (++files > 800) return;
        std::string low = to_lower(p);
        std::string namelow = low.substr(low.find_last_of('/') + 1);
        // 双扩展名（同 WIN.FILES 伪扩展校验）
        if (namelow.find('.', 1) != std::string::npos) {
            size_t last = namelow.rfind('.');
            std::string before = namelow.substr(0, last);
            size_t prev = before.rfind('.');
            std::string prevext = prev == std::string::npos ? "" : before.substr(prev);
            bool prev_archive = prevext == ".zip" || prevext == ".rar" || prevext == ".7z" ||
                                prevext == ".tar" || prevext == ".gz" || prevext == ".bz2" ||
                                prevext == ".xz" || prevext == ".tgz";
            bool prev_real = prevext.size() >= 2 && prevext[0] == '.';
            if (prev_real) {
                bool has_alpha = false;
                for (size_t k = 1; k < prevext.size(); ++k) {
                    char c = prevext[k];
                    if (c == '-' || c == '_') { prev_real = false; break; }
                    if (std::isalpha(static_cast<unsigned char>(c))) has_alpha = true;
                    else if (!std::isalnum(static_cast<unsigned char>(c))) { prev_real = false; break; }
                }
                if (!has_alpha) prev_real = false;
            }
            if (looks_exec_name_l(namelow) && !prev_archive && prev_real) {
                ++double_ext;
                Finding f;
                f.rule_id = "LNX.FILES.DOUBLEEXT.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "疑似双扩展名伪装: " + p + "——伪装线索，需人工查看内容";
                f.object_ref = p;
                f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                ctx.add_finding(f);
            }
        }
        // 基线比对
        if (!baseline.empty()) {
            auto it = baseline.find(low);
            if (it == baseline.end()) {
                std::string bn = low.substr(low.find_last_of('/') + 1);
                it = baseline.find(bn);
            }
            if (it != baseline.end()) {
                seen.insert(low);
                ReadResult r = read_text_file(p, 8 * 1024 * 1024);
                if (r.ok && r.raw_sha256 != it->second) {
                    ++mismatch;
                    Finding f;
                    f.rule_id = "LNX.FILES.BASELINE.001";
                    f.severity = "medium";
                    f.confidence = "high";
                    f.rationale = "基线哈希不一致: " + p +
                                  "（基线 " + it->second.substr(0, 16) + "… / 当前 " +
                                  r.raw_sha256.substr(0, 16) + "…）";
                    f.object_ref = p;
                    f.advice_id = "ADVICE.HASH.BASELINE.001";
                    ctx.add_finding(f);
                }
            }
        }
    }
}

void mod_files_l(ModuleCtx& ctx) {
    std::vector<std::string> dirs;
    for (const auto& d : ctx.config().extra_dirs) dirs.push_back(d);
    std::map<std::string, std::string> baseline;
    if (!ctx.config().baseline_path.empty()) {
        ctx.planned_source(ctx.config().baseline_path);
        ReadResult br = read_text_file(ctx.config().baseline_path, 4 * 1024 * 1024);
        if (br.ok) {
            for_each_line(br.content, [&](int, const std::string& line) {
                std::istringstream is(line);
                std::string path, sha, tok;
                while (is >> tok) {
                    if (tok.size() == 64) {
                        bool hexish = true;
                        for (char c : tok)
                            if (!std::isxdigit(static_cast<unsigned char>(c))) { hexish = false; break; }
                        if (hexish) { sha = to_lower(tok); continue; }
                    }
                    if (path.empty()) path = tok;
                }
                if (!path.empty() && sha.size() == 64) {
                    std::string lp = to_lower(path);
                    baseline[lp] = sha;
                    size_t bs = lp.find_last_of('/');
                    if (bs != std::string::npos) baseline[lp.substr(bs + 1)] = sha;
                }
            });
            ctx.checked_source("基线清单 " + std::to_string(baseline.size()) + " 条");
        } else {
            ctx.omitted_source(ctx.config().baseline_path, br.access_status);
        }
    }
    int files = 0, double_ext = 0, mismatch = 0;
    std::set<std::string> seen;
    for (const auto& d : dirs) {
        struct stat st{};
        if (lstat(d.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        ctx.planned_source(d);
        files_walk(ctx, d, 0, files, double_ext, mismatch, mismatch, baseline, seen);
        ctx.checked_source(d);
    }
    for (const auto& [low, sha] : baseline) {
        if (seen.count(low)) continue;
        ++mismatch;
        Finding f;
        f.rule_id = "LNX.FILES.BASELINE.MISS.001";
        f.severity = "low";
        f.confidence = "medium";
        f.rationale = "基线清单中的文件未找到: " + low;
        f.object_ref = low;
        f.advice_id = "ADVICE.HASH.BASELINE.001";
        ctx.add_finding(f);
    }
    Evidence e;
    e.source_kind = "dir";
    e.source_path = "LNX.FILES 巡检";
    e.payload = "files=" + std::to_string(files) + " double_ext=" + std::to_string(double_ext) +
                " baseline_total=" + std::to_string(baseline.size());
    ctx.add_evidence(e);
    if (dirs.empty()) ctx.note("未指定 --dir 附加目录（巡检跳过）");
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_c(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.CAPS", "1.0.0", "linux", [](ModuleCtx& c) { mod_caps(c); }});
    mods.push_back({"LNX.AT", "1.0.0", "linux", [](ModuleCtx& c) { mod_at(c); }});
    mods.push_back({"LNX.SHADOWPERM", "1.0.0", "linux", [](ModuleCtx& c) { mod_shadowperm(c); }});
    mods.push_back({"LNX.TIMERFACT", "1.0.0", "linux", [](ModuleCtx& c) { mod_timers(c); }});
    mods.push_back({"LNX.FILES", "1.0.0", "linux", [](ModuleCtx& c) { mod_files_l(c); }});
}

} // namespace ctfir::lnx
