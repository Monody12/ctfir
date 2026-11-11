// ctfir CLI — 只读应急扫描（契约：version/doctor/scan/explain/report；拒绝 fix/apply）
#include "core/session.hpp"
#include "core/report.hpp"
#include "core/advice.hpp"
#include "core/remediate.hpp"
#include "core/fixengine.hpp"
#include "core/util.hpp"
#include "platform/modules_registry.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <set>

namespace fs = std::filesystem;
#include <sstream>
#include <string>
#include <vector>

using namespace ctfir;

static bool read_file_all(const std::string& p, std::string& out) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

static bool load_session_dir(const std::string& dir, ScanSession& s,
                             std::vector<Finding>& fds, std::vector<Evidence>& evs,
                             std::string& err) {
    std::string t, reason;
    if (!read_file_all(dir + "/session.json", t) || !session_from_json(t, s, reason)) {
        err = "session.json 装载失败: " + reason; return false;
    }
    if (!read_file_all(dir + "/findings.json", t) || !findings_from_json(t, fds, reason)) {
        err = "findings.json 装载失败: " + reason; return false;
    }
    if (read_file_all(dir + "/evidence.json", t)) {
        if (!evidence_from_json(t, evs, reason)) { err = "evidence.json 装载失败: " + reason; return false; }
    }
    return true;
}

// --redact：IPv4 后两段掩码（报告导出脱敏；原始证据目录不改动）
static std::string mask_ips(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    size_t i = 0, n = in.size();
    while (i < n) {
        unsigned char c = in[i];
        if (c >= '0' && c <= '9') {
            int oct[4] = {0, 0, 0, 0}, dots = 0, j = i;
            bool ok = true, prev_digit = false;
            size_t start = i;
            for (; j < n; ++j) {
                char ch = in[j];
                if (ch >= '0' && ch <= '9') {
                    if (!prev_digit) { if (dots < 4) oct[dots] = 0; prev_digit = true; }
                    if (dots < 4) { oct[dots] = oct[dots] * 10 + (ch - '0'); if (oct[dots] > 255) ok = false; }
                    else { ok = false; }
                } else if (ch == '.' && prev_digit) {
                    ++dots; prev_digit = false;
                    if (dots > 3) { ok = false; }
                } else break;
            }
            if (ok && dots == 3 && prev_digit) {
                out += std::to_string(oct[0]) + "." + std::to_string(oct[1]) + ".x.x";
                i = j;
                continue;
            }
            out += in[i++];
        } else {
            out += in[i++];
        }
    }
    return out;
}

static int out_writable_fail(const std::string& out_dir) {
    std::fprintf(stderr, "[ctfir] 输出目录不可写: %s\n", out_dir.c_str());
    return 3;
}

static int cmd_version() {
    std::printf("{\"tool\":\"ctfir\",\"version\":\"%s\",\"read_only\":true}\n", kToolVersion);
    return 0;
}

static int cmd_doctor() {
    std::printf("{\"command\":\"doctor\",\n");
    std::printf(" \"tool_version\":\"%s\",\n", kToolVersion);
    std::printf(" \"os_name\":\"%s\",\n", detect_os_name().c_str());
    std::printf(" \"os_version\":\"%s\",\n", detect_os_version().c_str());
    std::printf(" \"os_arch\":\"%s\",\n", detect_os_arch().c_str());
    std::printf(" \"privilege\":\"%s\",\n", detect_privilege().c_str());
    std::printf(" \"schema_version\":%d,\n", kSchemaVersion);
    size_t n = build_platform_modules().size();
    std::printf(" \"modules_registered\":%zu,\n", n);
    std::printf(" \"notes\":\"只读工具；未实现/受限模块在报告中如实列出\"\n}\n");
    return 0;
}

// 应急响应 15 分钟总纲（内置离线帮助）
static int cmd_help() {
    std::printf(
        "ctfir %s — 应急响应 15 分钟总纲（配合本工具使用）\n"
        "==============================================\n"
        "拿到一台可疑机器后按此顺序处置（每步都可被 ctfir 覆盖）：\n"
        " 1. 存活现场：先取证（截图/内存如授权），不要急着重启\n"
        " 2. 进程与网络:   ctfir scan --out . --profile quick  → 看 WIN.PROCNET/WIN.PROCCMD/LNX.PROC\n"
        " 3. 账户:         看 WIN.ACC/LNX.ACC（隐藏/UID0/管理员组/4720 时间线）\n"
        " 4. 持久化:       任务/服务/启动项/cron/systemd/登录脚本\n"
        " 5. 登录日志:     WIN.EVTLOG(4624/4625/4720-4732) / LNX.LOGINS/LNX.LOG\n"
        " 6. Web 痕迹:     WIN.WEB / LNX.WEB（webshell 特征 + POST Top IP）\n"
        " 7. 执行痕迹:     Prefetch/ShimCache/bash_history/wtmp\n"
        " 8. 文件巡检:     --dir 自定目录 + --baseline 基线比对\n"
        " 9. 处置:         按报告\"处置手册\"六步执行（停用先于删除）\n"
        "10. 复查:         处置后重扫 + ctfir diff --a 旧 --b 新 确认变化\n"
        "\n速查手册: ctfir playbook <user|task|service|process|startup|hosts|sshkey|cron|profile|preload|webshell|hash|log>\n"
        "红线: 本工具只读，一切修改按手册人工执行。\n",
        kToolVersion);
    return 0;
}

// playbook：离线速查手册
static int cmd_playbook(int argc, char** argv) {
    static const std::pair<const char*, const char*> map[] = {
        {"user", "ADVICE.ACC.REVIEW.001"},       {"account", "ADVICE.ACC.REVIEW.001"},
        {"logonhide", "ADVICE.LOGIN_HIDE.REVIEW.001"}, {"task", "ADVICE.TASK.REVIEW.001"},
        {"service", "ADVICE.SVC.REVIEW.001"},    {"startup", "ADVICE.AUTORUN.REVIEW.001"},
        {"autorun", "ADVICE.AUTORUN.REVIEW.001"},{"hosts", "ADVICE.HOSTS.REVIEW.001"},
        {"sshkey", "ADVICE.SSHKEY.REVIEW.001"},  {"ssh", "ADVICE.SSHKEY.REVIEW.001"},
        {"cron", "ADVICE.CRON.REVIEW.001"},      {"at", "ADVICE.CRON.REVIEW.001"},
        {"timer", "ADVICE.CRON.REVIEW.001"},     {"profile", "ADVICE.PROFILE.REVIEW.001"},
        {"shell", "ADVICE.PROFILE.REVIEW.001"},  {"preload", "ADVICE.PRELOAD.REVIEW.001"},
        {"webshell", "ADVICE.WEBSHELL.REVIEW.001"}, {"web", "ADVICE.WEBSHELL.REVIEW.001"},
        {"process", "ADVICE.MINER.REVIEW.001"},  {"miner", "ADVICE.MINER.REVIEW.001"},
        {"hash", "ADVICE.HASH.BASELINE.001"},    {"baseline", "ADVICE.HASH.BASELINE.001"},
        {"log", "ADVICE.EVENTLOG.REVIEW.001"},   {"eventlog", "ADVICE.EVENTLOG.REVIEW.001"},
    };
    if (argc < 3) {
        std::fprintf(stderr,
            "用法: ctfir playbook <类型>\n"
            "类型: user logonhide task service startup hosts sshkey cron profile preload "
            "webshell process miner hash log\n");
        return 3;
    }
    std::string t = to_lower(argv[2]);
    for (const auto& [k, id] : map) {
        if (t == k) {
            const Advice* a = find_advice(id);
            if (a) {
                std::printf("【%s】(%s)\n%s\n", a->title, a->id, a->text);
                return 0;
            }
        }
    }
    std::fprintf(stderr, "[ctfir] 未知手册类型: %s\n", t.c_str());
    return 3;
}

// fix：受控修复（ADR-009）——默认只读不变；仅显式调用并确认后才执行白名单处置
static int cmd_fix(int argc, char** argv) {
    std::string dir, fid;
    bool yes = false, dry = false, all = false;
    for (int i = 2; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--session") && i + 1 < argc) dir = argv[++i];
        else if (!std::strcmp(argv[i], "--finding") && i + 1 < argc) fid = argv[++i];
        else if (!std::strcmp(argv[i], "--yes")) yes = true;
        else if (!std::strcmp(argv[i], "--dry-run")) dry = true;
        else if (!std::strcmp(argv[i], "--all")) all = true;
    }
    if (dir.empty() || (fid.empty() && !all)) {
        std::fprintf(stderr,
            "[ctfir] fix 需要 --session <目录> 与 --finding <规则ID> 或 --all\n"
            "  --dry-run  只打印处置计划不执行\n"
            "  --yes      跳过逐条确认（批量）\n"
            "说明: 修复仅覆盖白名单操作（账户/任务/服务/注册表值/hosts 行/进程/隔离），"
            "每步先备份到会话 fix-backup/ 并写 fix-journal.jsonl。\n");
        return 3;
    }
    ScanSession s; std::vector<Finding> fds; std::vector<Evidence> evs; std::string err;
    if (!load_session_dir(dir, s, fds, evs, err)) {
        std::fprintf(stderr, "[ctfir] %s\n", err.c_str());
        return 3;
    }
    FixContext fx;
    fx.session_dir = dir;
    fx.backup_dir = dir + "/fix-backup";
    fx.dry_run = dry;
    fx.assume_yes = yes;
    std::error_code ec;
    fs::create_directories(fs::u8path(fx.backup_dir), ec);
    int offered = 0;
    for (const auto& f : fds) {
        if (!all && !(f.rule_id == fid || starts_with(f.rule_id, fid))) continue;
        ++offered;
        RemediationPlan plan = plan_remediation(f);
        run_remediation(f, plan, fx);
    }
    if (!offered) {
        std::fprintf(stderr, "[ctfir] 未匹配到可处置的发现（%s）\n", all ? "会话无发现" : fid.c_str());
        return 3;
    }
    std::printf("[ctfir] 修复完成: 执行 %d / 跳过 %d / 不支持 %d——请重扫验证（diff 前后会话）\n",
                fx.executed, fx.skipped, fx.unsupported);
    return 0;
}

// diff：两次扫描对比（处置前后复查）
static int cmd_diff(int argc, char** argv) {
    std::string a, b;
    for (int i = 2; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--a") && i + 1 < argc) a = argv[++i];
        else if (!std::strcmp(argv[i], "--b") && i + 1 < argc) b = argv[++i];
    }
    if (a.empty() || b.empty()) {
        std::fprintf(stderr, "[ctfir] diff 需要 --a <会话目录> --b <会话目录>\n");
        return 3;
    }
    std::string t, err;
    std::vector<Finding> fa, fb;
    if (!read_file_all(a + "/findings.json", t) || !findings_from_json(t, fa, err) ||
        !read_file_all(b + "/findings.json", t) || !findings_from_json(t, fb, err)) {
        std::fprintf(stderr, "[ctfir] findings 装载失败: %s\n", err.c_str());
        return 3;
    }
    auto key = [](const Finding& f) { return f.rule_id + "@" + f.object_ref; };
    std::set<std::string> ka, kb;
    for (const auto& f : fa) ka.insert(key(f));
    for (const auto& f : fb) kb.insert(key(f));
    std::vector<std::string> resolved, added;
    for (const auto& k : ka) if (!kb.count(k)) resolved.push_back(k);   // 在 A 不在 B：已处置/消失
    for (const auto& k : kb) if (!ka.count(k)) added.push_back(k);      // 在 B 不在 A：新出现
    std::printf("{\"resolved\":%zu,\"added\":%zu}\n", resolved.size(), added.size());
    for (const auto& k : resolved) std::printf("[已消失] %s\n", k.c_str());
    for (const auto& k : added) std::printf("[新出现] %s\n", k.c_str());
    return resolved.empty() && added.empty() ? 0 : 1;
}

static int cmd_scan(const std::string& out_dir,
                    const std::vector<std::string>& extra_dirs = {},
                    const std::string& baseline = "",
                    const std::string& profile = "full") {
    ScanConfig cfg;
    cfg.out_dir = out_dir;
    cfg.extra_dirs = extra_dirs;
    cfg.baseline_path = baseline;
    cfg.profile = profile;
    Session sess(cfg);
    sess.set_host_info(detect_os_name(), detect_os_version(), detect_os_arch(), detect_privilege());

    std::string reason;
    if (!sess.prepare_out_dir(reason)) {
        std::fprintf(stderr, "[ctfir] %s\n", reason.c_str());
        return 3;
    }
    std::fprintf(stderr, "[ctfir] 会话 %s 开始（只读；输出 %s）\n",
                 sess.session().session_id.c_str(), out_dir.c_str());

    auto mods = build_platform_modules();
    // profile 过滤：quick=核心模块 / web=仅 Web / full=全部
    if (profile == "quick") {
        static const char* keep[] = {"WIN.ACC", "WIN.LOGINHIDE", "WIN.SVC", "WIN.AUTORUN",
                                     "WIN.HOSTS", "WIN.TASKS", "WIN.EVTLOG", "WIN.PROCCMD",
                                     "LNX.ACC", "LNX.SSH", "LNX.CRON", "LNX.SHELL",
                                     "LNX.PRELOAD", "LNX.HOSTS", "LNX.LOGINS"};
        std::vector<Session::ModuleDef> km;
        for (const auto& m : mods)
            for (const char* k : keep)
                if (m.id == k) { km.push_back(m); break; }
        mods = km;
    } else if (profile == "web") {
        std::vector<Session::ModuleDef> wm;
        for (const auto& m : mods)
            if (m.id == "WIN.WEB" || m.id == "LNX.WEB") wm.push_back(m);
        mods = wm;
    }
    sess.set_profile(profile);
    std::fprintf(stderr, "[ctfir] profile=%s 模块=%zu\n", profile.c_str(), mods.size());
    sess.run(mods);

    if (!sess.write_outputs(reason)) {
        std::fprintf(stderr, "[ctfir] 输出失败: %s\n", reason.c_str());
        return 3;
    }

    // stdout：纯 JSON 终报
    auto advices = advices_for(sess.findings());
    std::string report = build_json_report(sess.session(), sess.evidence(), sess.findings(), advices);
    std::fwrite(report.data(), 1, report.size(), stdout);
    std::fputs("\n", stdout);

    // 退出码契约（PLAN §10.2）：0=完整无发现 1=有发现 2=部分/受限 3=致命
    const auto& s = sess.session();
    bool any_fail = false, any_restricted = false, any_findings = !sess.findings().empty();
    for (const auto& m : s.modules) {
        if (m.status == ModuleStatus::ERROR || m.status == ModuleStatus::TIMEOUT) any_fail = true;
        if (m.status == ModuleStatus::PERMISSION_DENIED || m.status == ModuleStatus::SKIPPED) any_restricted = true;
    }
    if (any_fail || any_restricted) return 2;
    return any_findings ? 1 : 0;
}

static int cmd_explain(int argc, char** argv) {
    std::string dir, fid;
    for (int i = 2; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--session") && i + 1 < argc) dir = argv[++i];
        else if (!std::strcmp(argv[i], "--finding") && i + 1 < argc) fid = argv[++i];
    }
    if (dir.empty() || fid.empty()) {
        std::fprintf(stderr, "[ctfir] explain 需要 --session <目录> --finding <ID或规则ID>\n");
        return 3;
    }
    ScanSession s; std::vector<Finding> fds, match; std::vector<Evidence> evs; std::string err;
    if (!load_session_dir(dir, s, fds, evs, err)) {
        std::fprintf(stderr, "[ctfir] %s\n", err.c_str());
        return 3;
    }
    for (const auto& f : fds)
        if (f.finding_id == fid || f.rule_id == fid) match.push_back(f);
    if (match.empty()) {
        std::fprintf(stderr, "[ctfir] 未找到发现: %s\n", fid.c_str());
        return 3;
    }
    for (const auto& f : match) {
        std::printf("规则: %s (v%s)  平台: %s\n风险: %s  置信度: %s  证据信任: %s\n位置: %s\n依据: %s\n",
                    f.rule_id.c_str(), f.rule_version.c_str(), f.platform.c_str(),
                    f.severity.c_str(), f.confidence.c_str(), f.evidence_trust.c_str(),
                    f.object_ref.c_str(), f.rationale.c_str());
        if (!f.limitations.empty())
            std::printf("限制: %s\n", join(f.limitations, "；").c_str());
        for (const auto& e : evs) {
            for (const auto& id : f.evidence_ids) {
                if (e.evidence_id == id && !e.payload.empty())
                    std::printf("--- 证据 %s（%s）---\n%s\n",
                                e.evidence_id.c_str(), e.source_path.c_str(),
                                e.payload.substr(0, 4000).c_str());
            }
        }
        const Advice* a = find_advice(f.advice_id);
        if (a) std::printf("--- 建议（复制参考，工具不执行）---\n【%s】\n%s\n", a->title, a->text);
        else std::printf("(未挂接建议：按证据人工复核)\n");
    }
    return 0;
}

static int cmd_report(int argc, char** argv) {
    std::string dir;
    bool redact = false;
    for (int i = 2; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--session") && i + 1 < argc) dir = argv[++i];
        else if (!std::strcmp(argv[i], "--redact")) redact = true;
        else if (!std::strcmp(argv[i], "--format") && i + 1 < argc) ++i; // 仅支持 html，参数占位
    }
    if (dir.empty()) {
        std::fprintf(stderr, "[ctfir] report 需要 --session <目录> [--redact]\n");
        return 3;
    }
    ScanSession s; std::vector<Finding> fds; std::vector<Evidence> evs; std::string err;
    if (!load_session_dir(dir, s, fds, evs, err)) {
        std::fprintf(stderr, "[ctfir] %s\n", err.c_str());
        return 3;
    }
    if (redact) {
        for (auto& e : evs) e.payload = mask_ips(e.payload);
        for (auto& f : fds) f.rationale = mask_ips(f.rationale);
        std::fprintf(stderr, "[ctfir] 已启用脱敏（IPv4 后两段掩码）\n");
    }
    auto advices = advices_for(fds);
    std::string html = build_html_report(s, evs, fds, advices, beijing_time_str(now_utc_iso8601()));
    std::string out = dir + "/report.html";
    std::ofstream f(out, std::ios::binary);
    if (!f) { std::fprintf(stderr, "[ctfir] 写入失败: %s\n", out.c_str()); return 3; }
    f.write(html.data(), static_cast<std::streamsize>(html.size()));
    std::printf("{\"report\":\"%s\"}\n", out.c_str());
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "ctfir %s — CTF 只读应急扫描助手\n"
            "用法:\n"
            "  ctfir version\n"
            "  ctfir doctor\n"
            "  ctfir scan --out <目录>\n"
            "  ctfir explain --session <目录> --finding <ID或规则ID>\n"
            "  ctfir report --session <目录> [--redact]\n"
            "  （只读工具：不存在 apply/fix；修改一律按报告建议人工执行）\n",
            kToolVersion);
        return 3;
    }
    std::string cmd = argv[1];
    if (cmd == "version") return cmd_version();
    if (cmd == "doctor") return cmd_doctor();
    if (cmd == "fix" || cmd == "apply" || cmd == "repair") {
        std::fprintf(stderr, "[ctfir] 只读版本不支持修改类命令（%s）。请按报告建议人工执行。\n", cmd.c_str());
        return 3;
    }
    if (cmd == "scan") {
        std::string out_dir, baseline, profile = "full";
        std::vector<std::string> extra_dirs;
        for (int i = 2; i < argc; ++i) {
            if (!std::strcmp(argv[i], "--out") && i + 1 < argc) out_dir = argv[++i];
            else if (!std::strcmp(argv[i], "--baseline") && i + 1 < argc) baseline = argv[++i];
            else if (!std::strcmp(argv[i], "--dir") && i + 1 < argc) extra_dirs.push_back(argv[++i]);
            else if (!std::strcmp(argv[i], "--profile") && i + 1 < argc) profile = argv[++i];
        }
        if (out_dir.empty()) {
            std::fprintf(stderr, "[ctfir] scan 需要 --out <目录>\n");
            return 3;
        }
        if (!baseline.empty() || !extra_dirs.empty())
            std::fprintf(stderr, "[ctfir] 巡检目录 %zu 个；基线: %s\n",
                         extra_dirs.size(), baseline.empty() ? "无" : baseline.c_str());
        return cmd_scan(out_dir, extra_dirs, baseline, profile);
    }
    if (cmd == "fix") return cmd_fix(argc, argv);
    if (cmd == "help") return cmd_help();
    if (cmd == "playbook") return cmd_playbook(argc, argv);
    if (cmd == "diff") return cmd_diff(argc, argv);
    if (cmd == "explain") return cmd_explain(argc, argv);
    if (cmd == "report") return cmd_report(argc, argv);
    std::fprintf(stderr, "[ctfir] 未知命令: %s\n", cmd.c_str());
    return 3;
}
