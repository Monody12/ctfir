// ctfir CLI — 只读应急扫描（契约：version/doctor/scan/explain/report；拒绝 fix/apply）
#include "core/session.hpp"
#include "core/report.hpp"
#include "core/advice.hpp"
#include "core/util.hpp"
#include "platform/modules_registry.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
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

static int cmd_scan(const std::string& out_dir) {
    ScanConfig cfg;
    cfg.out_dir = out_dir;
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
        std::string out_dir;
        for (int i = 2; i < argc; ++i) {
            if (!std::strcmp(argv[i], "--out") && i + 1 < argc) out_dir = argv[++i];
        }
        if (out_dir.empty()) {
            std::fprintf(stderr, "[ctfir] scan 需要 --out <目录>\n");
            return 3;
        }
        return cmd_scan(out_dir);
    }
    if (cmd == "explain") return cmd_explain(argc, argv);
    if (cmd == "report") return cmd_report(argc, argv);
    std::fprintf(stderr, "[ctfir] 未知命令: %s\n", cmd.c_str());
    return 3;
}
