// Linux B 级模块：L07 systemd/init / L08 关键 ELF / L09 进程 / L10 SUID / L11 日志
#include "lnx_common.hpp"

#include <cstring>
#include <dirent.h>
#include <map>
#include <sys/stat.h>

namespace ctfir::lnx {

namespace {

// ---- L07 systemd / init.d / rc.local ----
void mod_systemd(ModuleCtx& ctx) {
    bool systemd_present = file_exists("/etc/systemd/system") || file_exists("/run/systemd/system");
    if (systemd_present) {
        // 递归 /etc/systemd/system（深度≤3，cap 500）
        std::vector<std::string> queue = {"/etc/systemd/system"};
        size_t files = 0;
        bool truncated = false;
        while (!queue.empty() && files < 500) {
            std::string dir = queue.back();
            queue.pop_back();
            for (const auto& p : list_dir(dir, 400, &truncated)) {
                struct stat st{};
                if (lstat(p.c_str(), &st) != 0) continue;
                if (S_ISDIR(st.st_mode)) {
                    if (files < 500) queue.push_back(p);
                    continue;
                }
                ++files;
                if (!ends_with(p, ".service") && !ends_with(p, ".timer")) continue;
                ReadResult r = read_source(ctx, p, false);
                if (!r.ok) continue;
                for_each_line(r.content, [&](int no, const std::string& line) {
                    std::string t = trim(line);
                    if (!starts_with(t, "Exec")) return;
                    auto hits = match_tokens(t);
                    if (hits.empty()) return;
                    std::string whys;
                    for (auto& [tk, why] : hits) whys += tk + " ";
                    Finding f;
                    f.rule_id = "LNX.PERSIST.SYSTEMD.001";
                    f.severity = "high";
                    f.confidence = "medium";
                    f.rationale = "systemd 单元 Exec 行含可疑特征: " + whys + "——自建服务属正常场景，需核对";
                    f.evidence_paths = {p};
                    f.object_ref = p + ":" + std::to_string(no);
                    f.limitations = {"未读取运行态 enabled 状态；drop-in 覆盖关系仅按文件逐个检查"};
                    f.advice_id = "ADVICE.CRON.REVIEW.001";
                    ctx.add_finding(f);
                });
            }
        }
        if (truncated) ctx.note("/etc/systemd/system 枚举超上限，超出部分未覆盖");
        // vendor 目录仅计数
        auto vendor = list_dir("/usr/lib/systemd/system", 2000);
        ctx.planned_source("/usr/lib/systemd/system");
        if (!vendor.empty()) {
            Evidence e;
            e.source_kind = "dir";
            e.source_path = "/usr/lib/systemd/system";
            e.payload = "vendor units: " + std::to_string(vendor.size()) + " 个（仅计数不逐个读取）";
            ctx.add_evidence(e);
            ctx.checked_source("/usr/lib/systemd/system");
        }
    } else {
        ctx.note("systemd 单元目录不存在（非 systemd 系统）：init.d/rc.local 兜底检查");
    }
    // init.d / rc.local 兜底
    for (const auto& f : list_dir("/etc/init.d", 200))
        read_source(ctx, f, false);
    ReadResult rc = read_source(ctx, "/etc/rc.local", false);
    if (rc.ok) {
        for_each_line(rc.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#' || !match_tokens(t).empty()) {
                if (match_tokens(t).empty()) return;
                Finding f;
                f.rule_id = "LNX.PERSIST.RCLOCAL.001";
                f.severity = "high";
                f.confidence = "medium";
                f.rationale = "rc.local 含可疑命令（第 " + std::to_string(no) + " 行）";
                f.evidence_paths = {"/etc/rc.local"};
                f.object_ref = "/etc/rc.local:" + std::to_string(no);
                f.advice_id = "ADVICE.CRON.REVIEW.001";
                ctx.add_finding(f);
            }
        });
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L08 关键 ELF 哈希留证 ----
void mod_elf(ModuleCtx& ctx) {
    const char* targets[] = {
        "/usr/bin/ps", "/usr/bin/ls", "/usr/bin/ss", "/usr/bin/netstat",
        "/usr/bin/top", "/usr/sbin/sshd", "/usr/bin/ssh", "/bin/ps", "/bin/ls",
        "/usr/bin/ps.static", "/bin/netstat", "/usr/bin/lsof"};
    std::set<std::string> seen;
    size_t hashed = 0;
    for (const char* t : targets) {
        std::string p(t);
        if (seen.count(p)) continue;
        seen.insert(p);
        if (!file_exists(p)) continue;
        ctx.planned_source(p);
        ReadResult r = read_text_file(p, 32 * 1024 * 1024);
        if (!r.ok) { ctx.omitted_source(p, r.access_status); continue; }
        Evidence e;
        e.source_kind = "file";
        e.source_path = p;
        e.sha256 = r.raw_sha256;
        e.payload = "(二进制不落 payload) size=" + std::to_string(r.raw_size);
        ctx.add_evidence(e);
        ctx.checked_source(p);
        ++hashed;
    }
    ctx.note("本模块仅留证（哈希），未内置可信基线：不能据此判定被篡改或安全");
    ctx.note("rpm/dpkg 包校验适配未纳入 v1（能力边界如实标注，不冒充已检查）");
    if (hashed == 0) ctx.note("未找到任何目标 ELF（容器/精简系统常见）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L09 进程 ----
void mod_proc(ModuleCtx& ctx) {
    auto pids = list_dir("/proc", 20000);
    size_t scanned = 0;
    bool budget_hit = false;
    for (const auto& pid_dir : pids) {
        // 仅数字目录
        const std::string base = pid_dir.substr(pid_dir.find_last_of('/') + 1);
        if (base.empty() || base[0] < '0' || base[0] > '9') continue;
        if (++scanned > 3000) { budget_hit = true; break; }
        if ((scanned % 200) == 0 && ctx.expired()) { budget_hit = true; break; }
        // cmdline
        ReadResult cmd = read_text_file(pid_dir + "/cmdline", 4096);
        std::string cmdline;
        if (cmd.ok) {
            cmdline = cmd.content;
            for (auto& c : cmdline)
                if (c == '\0') c = ' ';
            cmdline = trim(cmdline);
        }
        // exe 链接
        char buf[1024]{};
        ssize_t n = readlink((pid_dir + "/exe").c_str(), buf, sizeof(buf) - 1);
        std::string exe = n > 0 ? std::string(buf, static_cast<size_t>(n)) : "";
        bool deleted = exe.find(" (deleted)") != std::string::npos;

        if (!cmdline.empty()) {
            auto hits = match_tokens(cmdline);
            bool miner = false;
            for (auto& [tk, why] : hits)
                if (contains_ci(tk, "stratum") || contains_ci(tk, "xmrig") ||
                    contains_ci(tk, "kdevtmpfsi") || contains_ci(tk, "kinsing"))
                    miner = true;
            if (miner) {
                Finding f;
                f.rule_id = "LNX.PROC.MINER.001";
                f.severity = "high";
                f.confidence = "medium";
                f.rationale = "进程命令行含矿池/矿机特征: " + cmdline.substr(0, 300);
                f.evidence_paths = {pid_dir + "/cmdline"};
                f.object_ref = pid_dir;
                f.limitations = {"PID 可能复用；以证据快照为准"};
                f.advice_id = "ADVICE.MINER.REVIEW.001";
                ctx.add_finding(f);
                Evidence e;
                e.source_kind = "proc";
                e.source_path = pid_dir + "/cmdline";
                e.object_identity = "pid=" + base;
                e.payload = cmdline;
                ctx.add_evidence(e);
            }
        }
        if (deleted && !exe.empty()) {
            Finding f;
            f.rule_id = "LNX.PROC.DELETED.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "进程运行已删除的可执行文件: " + exe +
                          "（软件升级期属正常；配合时间与路径判断）";
            f.evidence_paths = {pid_dir + "/exe"};
            f.object_ref = pid_dir;
            f.advice_id = "ADVICE.MINER.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    ctx.note("扫描进程数: " + std::to_string(scanned) +
             (budget_hit ? "（预算截断，未覆盖全部 PID）" : ""));
    ctx.note("PID 复用/瞬逝进程为 /proc 快照固有局限；hidepid 下可见性受限");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L10 SUID/SGID ----
void mod_suid(ModuleCtx& ctx) {
    const char* dirs[] = {"/usr/bin", "/usr/sbin", "/bin", "/sbin"};
    const char* known[] = {
        "passwd", "sudo", "su", "mount", "umount", "ping", "chsh", "chfn",
        "newgrp", "gpasswd", "pkexec", "crontab", "at", "ssh-keysign",
        "fusermount", "fusermount3", "mount.nfs", "staprun", "mtr-packet",
        "unix_chkpwd", "userhelper", "pam_timestamp_check", "chage", "expiry",
        "wall", "write", "traceroute6.iputils", "ksu", "Xorg.wrap", "usernetctl",
        "userisdnctl", "pppd", "Xorg", "v4l2ucp"};
    std::set<std::string> allow(known, known + sizeof(known) / sizeof(known[0]));
    std::set<std::pair<unsigned long, unsigned long>> seen_inode;  // (dev,ino) 去重（/sbin 符号链接双列）
    size_t entries = 0;
    for (const char* d : dirs) {
        for (const auto& p : list_dir(d, 5000)) {
            if (++entries > 8000) { ctx.note("枚举超 8000 项截断"); goto done; }
            struct stat st{};
            if (lstat(p.c_str(), &st) != 0) continue;   // 不跟随符号链接
            if (!S_ISREG(st.st_mode)) continue;
            if (!seen_inode.insert({static_cast<unsigned long>(st.st_dev),
                                    static_cast<unsigned long>(st.st_ino)}).second)
                continue;
            bool suid = (st.st_mode & S_ISUID) != 0;
            bool sgid = (st.st_mode & S_ISGID) != 0;
            if (!suid && !sgid) continue;
            std::string name = p.substr(p.find_last_of('/') + 1);
            Evidence e;
            e.source_kind = "file";
            e.source_path = p;
            e.object_identity = "inode=" + std::to_string(st.st_ino);
            e.payload = std::string(suid ? "SUID" : "SGID") + " owner=" +
                        std::to_string(st.st_uid) + ":" + std::to_string(st.st_gid) +
                        " mode=" + std::to_string((st.st_mode & 07777));
            ctx.add_evidence(e);
            if (suid && !allow.count(name)) {
                Finding f;
                f.rule_id = "LNX.SUID.UNEXPECTED.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "非常见 SUID 程序: " + p +
                              "（发行版合法工具可能不在清单内，需人工核实）";
                f.evidence_paths = {p};
                f.limitations = {"白名单为常见发行版集合；自定义合法工具会命中"};
                f.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    }
done:
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L11 日志（登录线索） ----
void mod_log(ModuleCtx& ctx) {
    const char* logs[] = {"/var/log/secure", "/var/log/auth.log"};
    for (const char* lf : logs) {
        ReadResult r = read_source(ctx, lf, false, 8 * 1024 * 1024);
        if (!r.ok) continue;
        std::map<std::string, int> fail_ip;
        int root_ok = 0, fail_total = 0;
        for_each_line(r.content, [&](int, const std::string& line) {
            if (line.find("Failed password") != std::string::npos) {
                ++fail_total;
                // ... from <IP> port ...
                size_t fp = line.find(" from ");
                if (fp != std::string::npos) {
                    std::string rest = trim(line.substr(fp + 6));
                    size_t sp = rest.find(' ');
                    if (sp != std::string::npos) ++fail_ip[rest.substr(0, sp)];
                }
            }
            if (line.find("Accepted") != std::string::npos &&
                line.find(" for root") != std::string::npos)
                ++root_ok;
        });
        if (fail_total > 0) {
            std::string top;
            for (const auto& [ip, cnt] : fail_ip) top += ip + "×" + std::to_string(cnt) + " ";
            Evidence e;
            e.source_kind = "file";
            e.source_path = lf;
            e.payload = "failed_password=" + std::to_string(fail_total) +
                        " root_accepted=" + std::to_string(root_ok) +
                        "\ntop_source_ip: " + top;
            ctx.add_evidence(e);
            if (fail_total >= 20) {
                Finding f;
                f.rule_id = "LNX.LOG.AUTHFAIL.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "登录失败集中（" + std::to_string(fail_total) +
                              " 次）：可能为爆破，也可能是运维误输；Top 来源 IP 见证据";
                f.evidence_paths = {lf};
                f.limitations = {"日志可能轮转/缺失；缺失≠无事件"};
                f.advice_id = "ADVICE.EVENTLOG.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    }
    ctx.note("journalctl 适配未纳入 v1；日志缺失不充当无事件");
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_b(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.SYSTEMD", "1.0.0", "linux", [](ModuleCtx& c) { mod_systemd(c); }});
    mods.push_back({"LNX.ELF", "1.0.0", "linux", [](ModuleCtx& c) { mod_elf(c); }});
    mods.push_back({"LNX.PROC", "1.0.0", "linux", [](ModuleCtx& c) { mod_proc(c); }});
    mods.push_back({"LNX.SUID", "1.0.0", "linux", [](ModuleCtx& c) { mod_suid(c); }});
    mods.push_back({"LNX.LOG", "1.0.0", "linux", [](ModuleCtx& c) { mod_log(c); }});
}

} // namespace ctfir::lnx
