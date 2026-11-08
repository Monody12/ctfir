// ctfir CLI — 只读应急扫描（WP6 完成全部契约；当前已含 version/doctor/scan 骨架）
#include "core/session.hpp"
#include "core/report.hpp"
#include "platform/modules_registry.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace ctfir;

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

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "ctfir %s — CTF 只读应急扫描助手\n"
            "用法:\n"
            "  ctfir version\n"
            "  ctfir doctor\n"
            "  ctfir scan --out <目录>\n"
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
    std::fprintf(stderr, "[ctfir] 未知命令: %s\n", cmd.c_str());
    return 3;
}
