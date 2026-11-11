// Linux 基线核查模块族（v0.4）：空口令/弱口令、密码策略、登录限制、内核参数、
// 关键文件权限、不安全服务、内核版本漏洞线索、补丁与审计状态。
#include "lnx_common.hpp"
#include "platform/modules_registry.hpp"

#include <crypt.h>
#include <cstring>
#include <ctime>
#include <set>

namespace ctfir::lnx {

namespace {

// 弱口令比对表（现场只读比对，不保存哈希）
const char* kWeakPasswords[] = {"123456", "password", "root", "toor", "123456789",
                                "admin", "123123", "12345678", "qwerty", "abc123",
                                "1qaz2wsx", "password123", "P@ssw0rd", "linux", "centos"};

// passwd/shadow 解析：name:hash:...
struct AccRow { std::string name; std::string field2; int uid; };

static std::vector<AccRow> parse_passwd_like(const std::string& content) {
    std::vector<AccRow> out;
    for_each_line(content, [&](int, const std::string& line) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') return;
        int p1 = static_cast<int>(t.find(':'));
        int p2 = static_cast<int>(t.find(':', p1 + 1));
        int p3 = static_cast<int>(t.find(':', p2 + 1));
        if (p1 <= 0 || p2 < 0 || p3 < 0) return;
        out.push_back({t.substr(0, p1),
                       t.substr(p1 + 1, p2 - p1 - 1),
                       std::atoi(t.substr(p2 + 1, p3 - p2 - 1).c_str())});
    });
    return out;
}

// ---- LNX.BASE.PASSWORD：空口令 + 弱口令（现场比对）----
void mod_base_password(ModuleCtx& ctx) {
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    ReadResult sh = read_text_file("/etc/shadow", 1024 * 1024);
    std::map<std::string, std::string> shadow_hash; // name → hash 字段
    if (sh.ok) {
        for (const auto& r : parse_passwd_like(sh.content))
            if (!r.name.empty()) shadow_hash[r.name] = r.field2;
        ctx.checked_source("/etc/shadow（仅判定空/弱，不保存哈希）");
    }
    if (!pw.ok) { ctx.set_status(ModuleStatus::ERROR); return; }
    auto rows = parse_passwd_like(pw.content);
    for (const auto& r : rows) {
        std::string hash;
        // hash 取 shadow（优先）或 passwd 第二字段
        auto it = shadow_hash.find(r.name);
        if (it != shadow_hash.end()) hash = it->second;
        else if (r.field2 != "x" && r.field2 != "*" && !r.field2.empty()) hash = r.field2;
        else if (r.field2.empty()) {
            // passwd 第二字段为空 = 无密码（legacy 布局/无 shadow 条目）
            Finding f;
            f.rule_id = "LNX.BASE.EMPTYPWD.001";
            f.severity = "high";
            f.confidence = "high";
            f.rationale = "账户 \"" + r.name + "\" 为空口令（passwd 第二字段为空）——基线红线项";
            f.object_ref = "/etc/passwd:" + r.name;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
            continue;
        }
        else continue;

        if (hash.empty()) {
            Finding f;
            f.rule_id = "LNX.BASE.EMPTYPWD.001";
            f.severity = "high";
            f.confidence = "high";
            f.rationale = "账户 \"" + r.name + "\" 为空口令（可直接登录）——基线红线项";
            f.object_ref = "/etc/shadow:" + r.name;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
            continue;
        }
        if (hash[0] == '!' || hash[0] == '*' || starts_with(hash, "!")) continue; // 已锁定
        // 弱口令比对：crypt(候选, 原哈希) == 原哈希（只用 $id$salt$ 格式）
        if (hash.size() > 3 && hash[0] == '$') {
            size_t s2 = hash.find('$', 1);
            size_t s3 = hash.find('$', s2 + 1);
            if (s2 != std::string::npos && s3 != std::string::npos) {
                std::string setting = hash.substr(0, s3); // $id$salt$
                for (const char* cand : kWeakPasswords) {
                    char* c = crypt(cand, setting.c_str());
                    if (c && hash == c) {
                        Finding f;
                        f.rule_id = "LNX.BASE.WEAKPWD.001";
                        f.severity = "high";
                        f.confidence = "high";
                        f.rationale = "账户 \"" + r.name + "\" 使用弱口令（字典现场比对命中：已验证）——"
                                      "系统/服务被接管的最短路径";
                        f.object_ref = "/etc/shadow:" + r.name;
                        f.advice_id = "ADVICE.HARDEN.001";
                        ctx.add_finding(f);
                        break;
                    }
                }
            }
        }
    }
    ctx.note("弱口令比对在小字典内现场完成；哈希不写入任何证据");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.BASE.POLICY：密码策略 / 登录限制 / umask ----
void mod_base_policy(ModuleCtx& ctx) {
    // login.defs
    ReadResult ld = read_source(ctx, "/etc/login.defs", false);
    if (ld.ok) {
        for_each_line(ld.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            std::istringstream is(t);
            std::string k, v;
            if (!(is >> k >> v)) return;
            if (k == "PASS_MAX_DAYS" && std::atoi(v.c_str()) > 90) {
                Finding f;
                f.rule_id = "LNX.BASE.PWDMAX.001";
                f.severity = "low";
                f.confidence = "high";
                f.rationale = "密码最长使用期 " + v + " 天（基线建议 ≤90）";
                f.object_ref = "/etc/login.defs";
                f.advice_id = "ADVICE.HARDEN.001";
                ctx.add_finding(f);
            }
            if (k == "PASS_MIN_LEN" && std::atoi(v.c_str()) < 8) {
                Finding f;
                f.rule_id = "LNX.BASE.PWDLEN.001";
                f.severity = "medium";
                f.confidence = "high";
                f.rationale = "密码最小长度 " + v + "（基线建议 ≥8）";
                f.object_ref = "/etc/login.defs";
                f.advice_id = "ADVICE.HARDEN.001";
                ctx.add_finding(f);
            }
        });
    }
    // 系统账户可登录（uid<1000 且 shell 可登录）
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    if (pw.ok) {
        for_each_line(pw.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            int seen = 0, p6 = -1, p3 = -1, p1 = -1;
            for (int i = 0; i < (int)t.size(); ++i) {
                if (t[i] == ':') { ++seen; if (seen == 1) p1 = i; if (seen == 3) p3 = i; if (seen == 6) { p6 = i; break; } }
            }
            if (seen < 6 || p1 < 0 || p3 < 0 || p6 < 0) return;
            int uid = std::atoi(t.substr(p3 + 1).c_str());
            if (uid >= 1000) return;
            std::string shell = t.substr(p6 + 1);
            if (shell.empty() || shell == "/sbin/nologin" || shell == "/bin/false" ||
                shell == "/usr/sbin/nologin" || shell == "/bin/sync" || shell == "/sbin/shutdown" ||
                shell == "/sbin/halt")
                return;
            if (shell == "/bin/bash" || shell == "/bin/sh") {
                Finding f;
                f.rule_id = "LNX.BASE.SYSACCT.001";
                f.severity = "medium";
                f.confidence = "high";
                f.rationale = "系统账户（UID " + std::to_string(uid) + "）shell 为可登录: " +
                              t.substr(0, p1) + " → " + shell + "（基线建议 nologin）";
                f.object_ref = "/etc/passwd:" + t.substr(0, p1);
                f.advice_id = "ADVICE.HARDEN.001";
                ctx.add_finding(f);
            }
        });
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.BASE.KERNEL：内核参数 / 内核版本漏洞线索 ----
void mod_base_kernel(ModuleCtx& ctx) {
    struct KV { const char* path; const char* risky; const char* why; };
    static const KV kvs[] = {
        {"/proc/sys/net/ipv4/ip_forward", "1", "数据包转发开启（主机被当跳板的常见状态；路由服务器属正常）"},
        {"/proc/sys/fs/suid_dumpable", "2", "SUID 程序 core dump 开启（可能泄漏敏感内存）"},
        {"/proc/sys/kernel/kptr_restrict", "0", "内核指针未限制（信息泄露辅助）"},
        {"/proc/sys/kernel/dmesg_restrict", "0", "dmesg 未限制（信息泄露辅助）"},
    };
    for (const auto& kv : kvs) {
        ctx.planned_source(kv.path);
        ReadResult r = read_text_file(kv.path, 64);
        if (!r.ok) continue;
        std::string v = trim(r.content);
        if (v == kv.risky) {
            Finding f;
            f.rule_id = "LNX.BASE.KPARAM.001";
            f.severity = "low";
            f.confidence = "high";
            f.rationale = std::string("内核参数 ") + kv.path + " = " + v + "：" + kv.why;
            f.object_ref = kv.path;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
        ctx.checked_source(kv.path);
    }
    // 内核版本漏洞线索（静态范围表，提示需人工验证）
    std::string ver = detect_os_version(); // uname -r
    auto parse3 = [](const std::string& v, int out[3]) {
        int a = 0, b = 0, c = 0;
        if (sscanf(v.c_str(), "%d.%d.%d", &a, &b, &c) == 3) { out[0]=a; out[1]=b; out[2]=c; return true; }
        return false;
    };
    int k[3] = {0, 0, 0};
    if (parse3(ver, k)) {
        auto lt = [](const int a[3], int x, int y, int z) {
            if (a[0] != x) return a[0] < x;
            if (a[1] != y) return a[1] < y;
            return a[2] < z;
        };
        bool dirtycow = (k[0] == 4 && lt(k, 4, 8, 3)) || (k[0] < 4);
        bool dirtypipe = (k[0] == 5 && k[1] >= 8) || (k[0] > 5);
        if (dirtycow) {
            Finding f;
            f.rule_id = "LNX.BASE.KCVE.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "内核版本 " + ver + " 疑似受 DirtyCow（CVE-2016-5195）影响——本地提权经典漏洞，需人工验证补丁情况";
            f.object_ref = "uname -r";
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
        if (dirtypipe) {
            Finding f;
            f.rule_id = "LNX.BASE.KCVE.002";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "内核版本 " + ver + " 疑似受 DirtyPipe（CVE-2022-0847）影响——需人工验证补丁情况";
            f.object_ref = "uname -r";
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }
    // pkexec（CVE-2021-4034 存在面）
    if (file_exists("/usr/bin/pkexec"))
        ctx.note("/usr/bin/pkexec 存在（CVE-2021-4034 PwnKit 需人工核对 polkit 补丁版本）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.BASE.SERVICES：不安全远程服务 / SNMP 默认团体字 / 远程日志 / NTP ----
void mod_base_services(ModuleCtx& ctx) {
    // systemd wants 目录中的不安全服务
    for (const auto& p : list_dir("/etc/systemd/system/multi-user.target.wants", 200)) {
        std::string low = to_lower(p);
        std::string name = p.substr(p.find_last_of('/') + 1);
        if (low.find("telnet") != std::string::npos || low.find("vsftpd") != std::string::npos ||
            low.find("tftp") != std::string::npos || low.find("rsh") != std::string::npos) {
            Finding f;
            f.rule_id = "LNX.BASE.UNSAFESVC.001";
            f.severity = "medium";
            f.confidence = "high";
            f.rationale = "不安全远程服务已启用: " + name + "（明文协议，凭据可被嗅探）";
            f.object_ref = p;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }
    // SNMP 默认团体字
    ReadResult snmp = read_source(ctx, "/etc/snmp/snmpd.conf", false);
    if (snmp.ok && contains_ci(snmp.content, "public")) {
        Finding f;
        f.rule_id = "LNX.BASE.SNMP.001";
        f.severity = "medium";
        f.confidence = "medium";
        f.rationale = "SNMP 使用默认团体字 public（设备信息可被枚举）";
        f.object_ref = "/etc/snmp/snmpd.conf";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }
    // 远程日志 / NTP 状态（note 级）
    ReadResult rs = read_source(ctx, "/etc/rsyslog.conf", false);
    if (rs.ok && rs.content.find("@") != std::string::npos)
        ctx.note("rsyslog 配置了远程日志转发（@ 行）——审计集中化已启用");
    else
        ctx.note("基线提示：未检测到远程日志转发（日志集中审计缺失）");
    // /etc/environment PATH
    ReadResult env = read_source(ctx, "/etc/environment", false);
    if (env.ok) {
        for_each_line(env.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (starts_with(t, "PATH=") && (t.find("/tmp") != std::string::npos || t.find("/dev/shm") != std::string::npos)) {
                Finding f;
                f.rule_id = "LNX.BASE.ENVPATH.001";
                f.severity = "medium";
                f.confidence = "high";
                f.rationale = "/etc/environment PATH 含临时目录: " + t.substr(0, 150);
                f.object_ref = "/etc/environment:" + std::to_string(no);
                f.advice_id = "ADVICE.HARDEN.001";
                ctx.add_finding(f);
            }
        });
        ctx.checked_source("/etc/environment");
    }
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_e(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.BASE.PWD", "1.0.0", "linux", [](ModuleCtx& c) { mod_base_password(c); }});
    mods.push_back({"LNX.BASE.POLICY", "1.0.0", "linux", [](ModuleCtx& c) { mod_base_policy(c); }});
    mods.push_back({"LNX.BASE.KERNEL", "1.0.0", "linux", [](ModuleCtx& c) { mod_base_kernel(c); }});
    mods.push_back({"LNX.BASE.SERVICES", "1.0.0", "linux", [](ModuleCtx& c) { mod_base_services(c); }});
}

} // namespace ctfir::lnx
