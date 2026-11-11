// Linux v0.5-R10 遗漏补齐：系统命令替换 / SSH Port / 最近修改文件 / 进程名不匹配
#include "lnx_common.hpp"
#include "platform/modules_registry.hpp"

#include <cstring>
#include <ctime>
#include <set>
#include <sys/stat.h>

namespace ctfir::lnx {

namespace {

// ---- LNX.BASE.CMDSIZE：系统命令大小/时间异常（假 ls 检测）----
void mod_cmdsize(ModuleCtx& ctx) {
    // 常见系统命令的合理大小范围（bytes）——低于最小值或高于最大值为可疑
    struct CmdCheck { const char* path; long min_size; long max_size; };
    static const CmdCheck cmds[] = {
        {"/bin/ls",         50000, 500000},
        {"/usr/bin/ls",     50000, 500000},
        {"/bin/ps",         20000, 500000},
        {"/usr/bin/ps",     20000, 500000},
        {"/bin/netstat",    20000, 500000},
        {"/bin/cat",        20000, 200000},
        {"/bin/cp",         20000, 200000},
        {"/bin/mv",         20000, 200000},
        {"/bin/rm",         20000, 200000},
        {"/usr/bin/find",   50000, 500000},
        {"/usr/bin/wget",   100000, 1000000},
        {"/usr/bin/curl",   100000, 2000000},
        {"/bin/bash",       500000, 3000000},
        {"/bin/sh",         100000, 3000000},
        {"/usr/bin/ss",     20000, 300000},
        {"/usr/bin/top",    50000, 500000},
        {"/usr/bin/ssh",    300000, 2000000},
        {"/usr/sbin/sshd",  300000, 3000000},
    };
    int checked = 0, flagged = 0;
    for (const auto& cmd : cmds) {
        struct stat st{};
        if (stat(cmd.path, &st) != 0) continue; // 命令不存在（精简系统）
        ++checked;
        long sz = static_cast<long>(st.st_size);
        bool suspicious = false;
        std::string reason;
        if (sz < cmd.min_size) {
            suspicious = true;
            reason = "文件大小 " + std::to_string(sz) + "B 异常偏小（预期 ≥" + std::to_string(cmd.min_size) + "B）——可能被替换为恶意脚本";
        } else if (sz > cmd.max_size) {
            suspicious = true;
            reason = "文件大小 " + std::to_string(sz) + "B 异常偏大（预期 ≤" + std::to_string(cmd.max_size) + "B）——可能被加壳或捆绑";
        }
        // mtime 异常：如果修改时间在最近 7 天内且不是包管理器时间 → 线索
        time_t now = time(nullptr);
        time_t age = now - st.st_mtime;
        bool recent = age < 7 * 86400;
        if (suspicious) {
            ++flagged;
            Finding f;
            f.rule_id = "LNX.BASE.CMDSIZE.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "系统命令疑似被替换: " + std::string(cmd.path) + "（" + reason + "）";
            f.object_ref = cmd.path;
            f.evidence_paths = {cmd.path};
            f.limitations = {"大小阈值基于常见发行版统计；不同发行版/编译选项可能差异较大——需人工用 rpm -Va / dpkg -V 确认"};
            f.advice_id = "ADVICE.HASH.BASELINE.001";
            ctx.add_finding(f);
        } else if (recent) {
            Finding f;
            f.rule_id = "LNX.BASE.CMDRECENT.001";
            f.severity = "low";
            f.confidence = "low";
            f.rationale = "系统命令最近 7 天内被修改: " + std::string(cmd.path) + "（可能是系统更新，也可能被替换——需核对包管理器）";
            f.object_ref = cmd.path;
            f.advice_id = "ADVICE.HASH.BASELINE.001";
            ctx.add_finding(f);
        }
    }
    if (checked == 0) ctx.note("未找到任何目标命令（精简容器）");
    ctx.note("系统命令替换检测基于大小阈值 + 修改时间——精确判定需 rpm -Va / dpkg -V 与包管理器核对");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.SSH.PORT：SSH 端口提取 ----
void mod_sshport(ModuleCtx& ctx) {
    ReadResult r = read_source(ctx, "/etc/ssh/sshd_config", false);
    if (!r.ok) { ctx.set_status(ModuleStatus::PASS); return; }
    std::vector<std::string> ports;
    int port_line = 0;
    for_each_line(r.content, [&](int no, const std::string& line) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') return;
        if (starts_with(t, "Port ") || starts_with(t, "Port\t")) {
            std::string val = trim(t.substr(5));
            if (!val.empty()) { ports.push_back(val); port_line = no; }
        }
    });
    if (!ports.empty()) {
        std::string port_str = join(ports, ",");
        if (ports.size() == 1 && ports[0] == "22") {
            ctx.note("SSH 端口: 22（默认）");
        } else {
            Finding f;
            f.rule_id = "LNX.SSH.PORT.001";
            f.severity = "low";
            f.confidence = "high";
            f.rationale = "SSH 监听非默认端口: " + port_str + "（后门 SSH 可能跑在非标端口上）";
            f.object_ref = "/etc/ssh/sshd_config:" + std::to_string(port_line);
            f.advice_id = "ADVICE.SSHKEY.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.RECENT：最近 7 天修改的可执行/脚本文件 ----
void mod_recent(ModuleCtx& ctx) {
    time_t now = time(nullptr);
    std::vector<std::string> dirs = {"/etc", "/usr/local/bin", "/usr/local/sbin", "/root"};
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    if (pw.ok) {
        for_each_line(pw.content, [&](int, const std::string& line) {
            int seen = 0, p5 = 0, p6 = 0;
            for (int i = 0; i < (int)line.size(); ++i) {
                if (line[i] == ':') { ++seen; if (seen == 5) p5 = i; if (seen == 6) { p6 = i; break; } }
            }
            if (seen < 6) return;
            std::string home = line.substr(p5 + 1, p6 - p5 - 1);
            if (home[0] == '/') dirs.push_back(home + "/.ssh");
        });
    }
    int found = 0;
    for (const auto& d : dirs) {
        for (const auto& p : list_dir(d, 500)) {
            if (ctx.expired()) { ctx.note("预算截断"); break; }
            struct stat st{};
            if (lstat(p.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
            time_t age = now - st.st_mtime;
            if (age > 7 * 86400) continue; // 7 天内
            std::string low = to_lower(p);
            bool is_exec = (st.st_mode & S_IXUSR) || ends_with(low, ".sh") ||
                           ends_with(low, ".py") || ends_with(low, ".php") ||
                           ends_with(low, ".conf") || ends_with(low, ".cfg");
            if (!is_exec) continue;
            ++found;
            if (found > 20) continue; // 超过 20 条不再逐条报
            char tbuf[24];
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M", localtime(&st.st_mtime));
            Finding f;
            f.rule_id = "LNX.BASE.RECENT.001";
            f.severity = "low";
            f.confidence = "low";
            f.rationale = "最近 7 天内新增/修改的可执行/配置文件: " + p + "（mtime " + tbuf + "）——新投毒线索";
            f.object_ref = p;
            f.advice_id = "ADVICE.HASH.BASELINE.001";
            ctx.add_finding(f);
        }
    }
    ctx.note("最近修改文件扫描: " + std::to_string(found) + " 个（7 天窗口，仅可执行/配置文件）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.PROC.NAME.MISMATCH：进程名与 exe 不匹配（命令名替换检测）----
void mod_procmismatch(ModuleCtx& ctx) {
    for (const auto& p : list_dir("/proc", 20000)) {
        std::string base = p.substr(p.find_last_of('/') + 1);
        if (base.empty() || base[0] < '0' || base[0] > '9') continue;
        if (ctx.expired()) { ctx.note("预算截断"); break; }
        // 读 cmdline 第一个参数（argv[0]）
        ReadResult cmd = read_text_file(p + "/cmdline", 512);
        if (!cmd.ok || cmd.content.empty()) continue;
        std::string argv0 = cmd.content.substr(0, cmd.content.find('\0'));
        // argv[0] 通常是完整路径，取最后一段作为"声称的命令名"
        size_t slash = argv0.find_last_of('/');
        std::string claimed = slash == std::string::npos ? argv0 : argv0.substr(slash + 1);
        if (claimed.empty()) continue;
        // 读 exe 符号链接（真实二进制路径）
        char buf[1024]{};
        ssize_t n = readlink((p + "/exe").c_str(), buf, sizeof(buf) - 1);
        if (n <= 0) continue;
        std::string exe(buf, static_cast<size_t>(n));
        size_t eslash = exe.find_last_of('/');
        std::string exe_name = eslash == std::string::npos ? exe : exe.substr(eslash + 1);
        // 比较（允许常见差异：bash vs -bash, [kworker] 等）
        if (claimed != exe_name && claimed != "-" + exe_name &&
            !claimed.empty() && !exe_name.empty()) {
            // 排除正常场景（python3 脚本名不同、busybox 多调用等）
            if (exe_name.find("python") == 0 || exe_name.find("perl") == 0 ||
                exe_name.find("busybox") == 0 || exe_name.find("java") == 0) continue;
            Finding f;
            f.rule_id = "LNX.PROC.NAMEMISMATCH.001";
            f.severity = "medium";
            f.confidence = "low";
            f.rationale = "进程名与 exe 不匹配: PID " + base + " 声称 " + claimed +
                          " 但 exe 是 " + exe + "（可能是替换了进程名的后门）";
            f.object_ref = "PID " + base;
            f.evidence_paths = {exe};
            f.limitations = {"符号链接/wrapper 脚本/解释器属正常场景"};
            f.advice_id = "ADVICE.MINER.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    ctx.note("进程名不匹配检测基于 /proc/PID/exe 与 cmdline argv[0] 对比——排除解释器和 wrapper 属正常");
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_i(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.BASE.CMDSIZE", "1.0.0", "linux", [](ModuleCtx& c) { mod_cmdsize(c); }});
    mods.push_back({"LNX.SSH.PORT", "1.0.0", "linux", [](ModuleCtx& c) { mod_sshport(c); }});
    mods.push_back({"LNX.BASE.RECENT", "1.0.0", "linux", [](ModuleCtx& c) { mod_recent(c); }});
    mods.push_back({"LNX.PROC.NAME", "1.0.0", "linux", [](ModuleCtx& c) { mod_procmismatch(c); }});
}

} // namespace ctfir::lnx
