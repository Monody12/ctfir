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

} // namespace

void register_mods_c(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.CAPS", "1.0.0", "linux", [](ModuleCtx& c) { mod_caps(c); }});
    mods.push_back({"LNX.AT", "1.0.0", "linux", [](ModuleCtx& c) { mod_at(c); }});
    mods.push_back({"LNX.SHADOWPERM", "1.0.0", "linux", [](ModuleCtx& c) { mod_shadowperm(c); }});
    mods.push_back({"LNX.TIMERFACT", "1.0.0", "linux", [](ModuleCtx& c) { mod_timers(c); }});
}

} // namespace ctfir::lnx
