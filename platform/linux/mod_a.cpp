// Linux A 级模块：L01 账户 / L02 SSH / L03 cron / L04 shell 持久化 / L05 preload / L06 hosts / L13 痕迹
#include "lnx_common.hpp"
#include "core/lnx_heuristics.hpp"
#include "core/account_policy.hpp"

#include <cstring>
#include <map>
#include <set>

namespace ctfir::lnx {

namespace {

// ---- L01 本地账户/组/sudoers ----
void mod_acc(ModuleCtx& ctx) {
    ReadResult pw = read_source(ctx, "/etc/passwd", true);
    ReadResult gr = read_source(ctx, "/etc/group", true);

    ReadResult nss = read_source(ctx, "/etc/nsswitch.conf", false);
    ctx.note("账户范围仅本地文件；不执行getent，不查询SSSD/LDAP/NIS/域目录；CentOS版本与实际内核须另核对");
    if(nss.ok) for_each_line(nss.content,[&](int,const std::string& line) {
        if(starts_with(trim(line),"passwd:")) {
            Evidence e;e.source_kind="file";e.source_path="/etc/nsswitch.conf";e.payload=trim(line)+"; local-files-only, no external NSS query";ctx.add_evidence(e);
            if(account_nss_has_external(trim(line)))ctx.omitted_source("external NSS accounts","offline scope: provider configured but not enumerated; local PASS does not exclude domain users");
        }
    });
    if (pw.ok) {
        std::map<std::uint32_t, std::vector<std::string>> uid_names;
        for_each_line(pw.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            LocalPasswdRecord rec;
            if(!parse_local_passwd(t,rec)) {
                if(t[0]!='+'&&t[0]!='-')ctx.omitted_source("/etc/passwd:"+std::to_string(no),"malformed local record, not interpreted as UID0");
                return;
            }
            const std::string& name=rec.name;const auto uid=rec.uid;
            uid_names[uid].push_back(name);
            if (uid == 0 && name != "root") {
                Finding f;
                f.rule_id = "LNX.ACC.UID0.001";
                f.severity = "high";
                f.confidence = "medium"; // 事实确定；是否授权需人工核实（PLAN §9.4 示例口径）
                f.rationale = "账户 " + name + " 的 UID=0（/etc/passwd 第 " + std::to_string(no) +
                              " 行），共享root内核权限；不是已证实恶意，需核实授权/来源/业务依赖";
                f.evidence_paths = {"/etc/passwd"};
                f.object_ref = "/etc/passwd:" + name;
                f.limitations = {"仅本地文件账户；NSS/域账户不在范围；不能证明内核未被控制"};
                f.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(f);
            }
        });
        for (const auto& [uid, names] : uid_names) {
            if (names.size() > 1) {
                Finding f;
                f.rule_id = "LNX.ACC.DUPUID.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "UID " + std::to_string(uid) + " 被多个账户共享: " + join(names, ", ") +
                              "（授权运维可合法共享；需核实）";
                f.evidence_paths = {"/etc/passwd"};
                std::string shown = names[0];
                for (const auto& n : names)
                    if (n != "root") { shown = n; break; }
                f.object_ref = "/etc/passwd:" + shown;
                f.limitations = {"重复 UID 本身不必然恶意"};
                f.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    }

    if (gr.ok) {
        for_each_line(gr.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            // name:pw:gid:members
            int p1 = static_cast<int>(t.find(':'));
            int p2 = static_cast<int>(t.find(':', p1 + 1));
            int p3 = static_cast<int>(t.find(':', p2 + 1));
            if (p1 <= 0 || p2 < 0 || p3 < 0 || t[0]=='+' || t[0]=='-') return;
            std::uint32_t gid=0;
            if(!account_uint32(t.substr(p2 + 1, p3 - p2 - 1),gid))return;
            std::string gname = t.substr(0, p1);
            std::string members = t.substr(p3 + 1);
            std::istringstream member_stream(members);std::string member;bool nonroot=false;
            while(std::getline(member_stream,member,','))if(!member.empty()&&member!="root")nonroot=true;
            if (gid == 0 && nonroot) {
                Finding f;
                f.rule_id = "LNX.ACC.GID0.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "组 " + gname + " 的 GID=0，成员: " + members + "（授权运维可合法；需核实）";
                f.evidence_paths = {"/etc/group"};
                f.object_ref = "/etc/group:" + gname;
                f.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(f);
            }
        });
    }

    // sudoers：可读部分（主文件 + sudoers.d）
    ReadResult su = read_source(ctx, "/etc/sudoers", false);
    if (su.ok) {
        for_each_line(su.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            if (contains_ci(t, "NOPASSWD") && contains_ci(t, "ALL")) {
                size_t sp = t.find_first_of(" \t");
                std::string who = sp == std::string::npos ? t : t.substr(0, sp);
                Finding f;
                f.rule_id = "LNX.ACC.SUDOERS.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "sudoers 第 " + std::to_string(no) + " 行给 " + who +
                              " 免密 ALL：若非授权配置属高危";
                f.evidence_paths = {"/etc/sudoers"};
                f.object_ref = "/etc/sudoers:" + std::to_string(no);
                f.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(f);
            }
        });
    }
    for (const auto& f : list_dir("/etc/sudoers.d", 100)) {
        ReadResult r = read_source(ctx, f, false);
        if (!r.ok) continue;
        for_each_line(r.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            if (contains_ci(t, "NOPASSWD") && contains_ci(t, "ALL")) {
                size_t sp = t.find_first_of(" \t");
                std::string who = sp == std::string::npos ? t : t.substr(0, sp);
                Finding fd;
                fd.rule_id = "LNX.ACC.SUDOERS.001";
                fd.severity = "medium";
                fd.confidence = "medium";
                fd.rationale = "sudoers.d 给 " + who + " 免密 ALL：" + f + " 第 " +
                               std::to_string(no) + " 行";
                fd.evidence_paths = {f};
                fd.object_ref = f + ":" + std::to_string(no);
                fd.advice_id = "ADVICE.ACC.REVIEW.001";
                ctx.add_finding(fd);
            }
        });
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L02 SSH ----
void mod_ssh(ModuleCtx& ctx) {
    // sshd_config + Include（一层）
    ReadResult cfg = read_source(ctx, "/etc/ssh/sshd_config", false);
    std::vector<std::string> include_files;
    if (cfg.ok) {
        for_each_line(cfg.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            if (starts_with(t, "PermitRootLogin") && contains_ci(t, "yes")) {
                Finding f;
                f.rule_id = "LNX.SSH.CONFIG.001";
                f.severity = "low";
                f.confidence = "high";
                f.rationale = "sshd_config 允许 root 直接登录（PermitRootLogin yes）——是否允许需结合安全基线核实";
                f.evidence_paths = {"/etc/ssh/sshd_config"};
                f.object_ref = "/etc/ssh/sshd_config:" + std::to_string(no);
                f.advice_id = "ADVICE.SSHKEY.REVIEW.001";
                ctx.add_finding(f);
            }
            if (starts_with(t, "PasswordAuthentication") && contains_ci(t, "yes")) {
                Finding f;
                f.rule_id = "LNX.SSH.PWDAUTH.001";
                f.severity = "low";
                f.confidence = "high";
                f.rationale = "sshd_config 允许口令登录（PasswordAuthentication yes）——爆破面，基线建议改密钥登录";
                f.object_ref = "/etc/ssh/sshd_config:" + std::to_string(no);
                f.advice_id = "ADVICE.SSHKEY.REVIEW.001";
                ctx.add_finding(f);
            }
            if (starts_with(t, "MaxAuthTries")) {
                int tries = std::atoi(trim(t.substr(13)).c_str());
                if (tries > 6) {
                    Finding f;
                    f.rule_id = "LNX.SSH.MAXAUTH.001";
                    f.severity = "low";
                    f.confidence = "high";
                    f.rationale = "MaxAuthTries=" + std::to_string(tries) +
                                  "（>6）——单连接可尝试更多口令，利于爆破";
                    f.object_ref = "/etc/ssh/sshd_config:" + std::to_string(no);
                    f.advice_id = "ADVICE.HARDEN.001";
                    ctx.add_finding(f);
                }
            }
            if (starts_with(t, "Include")) {
                std::string inc = trim(t.substr(7));
                if (!inc.empty()) include_files.push_back(inc);
            }
            if (starts_with(t, "AuthorizedKeysFile")) {
                ctx.note("AuthorizedKeysFile 被自定义：" + t + "（默认路径之外的位置不在本模块覆盖）");
            }
        });
        ctx.note("Match 块未做条件求值：其内部指令可能改变默认行为");
    }
    for (const auto& inc : include_files) {
        std::string p = inc[0] == '/' ? inc : "/etc/ssh/" + inc;
        read_source(ctx, p, false);
    }
    for (const auto& d : list_dir("/etc/ssh/sshd_config.d", 50))
        read_source(ctx, d, false);

    // 各用户 authorized_keys / 私钥存在性（不读取私钥内容）
    std::set<std::string> seen_ak, seen_cfg, seen_hidden;
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    if (pw.ok) {
        for_each_line(pw.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            int p1 = static_cast<int>(t.find(':'));
            int p5 = 0, p6 = 0, seen = 0;
            for (int i = 0; i < static_cast<int>(t.size()); ++i) {
                if (t[i] == ':') { ++seen; if (seen == 5) p5 = i; if (seen == 6) { p6 = i; break; } }
            }
            if (seen < 6) return;
            std::string home = t.substr(p5 + 1, p6 - p5 - 1);
            std::string name = t.substr(0, p1);
            if (home.empty() || home[0] != '/') return;
            for (const char* kn : {"authorized_keys", "authorized_keys2"}) {
            std::string ak = home + "/.ssh/" + kn;
            ReadResult r = read_source(ctx, ak, false);
            if (r.ok && !trim(r.content).empty()) {
                if (!seen_ak.insert(ak).second) continue;
                // 指纹 + 危险选项
                std::vector<std::string> fingerprints;
                bool has_cmd = false;
                for_each_line(r.content, [&](int lno, const std::string& l) {
                    std::string k = trim(l);
                    if (k.empty() || k[0] == '#') return;
                    // options 形态：command="..." keytype base64 comment
                    if (starts_with(k, "command=")) has_cmd = true;
                    // 取最后一段 base64（key blob）：按空格倒序找第二个字段
                    std::istringstream is(k);
                    std::vector<std::string> parts;
                    std::string w;
                    while (is >> w) parts.push_back(w);
                    if (parts.size() >= 2) {
                        std::string blob;
                        // keytype base64 [comment]：base64 是倒数第 2 段（有 comment）或第 2 段
                        for (size_t i = parts.size() - 1; i >= 1; --i) {
                            if (base64_decode(parts[i], blob) && blob.size() > 16) break;
                        }
                        if (!blob.empty())
                            fingerprints.push_back(Sha256::hex_of(blob.data(), blob.size()).substr(0, 16));
                    }
                    (void)lno;
                });
                Finding f;
                f.rule_id = "LNX.SSH.AUTHKEY.001";
                f.severity = "low";
                f.confidence = "high";
                f.rationale = "用户 " + name + " 存在授权公钥 " +
                              std::to_string(fingerprints.size()) + " 条（指纹前 16 位: " +
                              (fingerprints.empty() ? "解析失败" : join(fingerprints, ",")) +
                              "）——公钥存在属正常，需逐条核对归属";
                f.evidence_paths = {ak};
                f.object_ref = ak;
                f.limitations = {"仅记录指纹不保存公钥/私钥本体；options 语义未全量求值"};
                f.advice_id = "ADVICE.SSHKEY.REVIEW.001";
                if (has_cmd) {
                    f.severity = "medium";
                    f.rationale += "；存在 forced command（command=）选项，属高危特征需优先核实";
                }
                ctx.add_finding(f);
            }
            } // authorized_keys / authorized_keys2
            // .ssh/config ProxyCommand 后门
            {
                std::string cfg = home + "/.ssh/config";
                ReadResult cr = read_source(ctx, cfg, false);
                if (cr.ok && seen_cfg.insert(cfg).second) {
                    for_each_line(cr.content, [&](int lno, const std::string& l) {
                        std::string tl = trim(l);
                        if (contains_ci(tl, "ProxyCommand") &&
                            (contains_ci(tl, "nc ") || contains_ci(tl, "bash") || contains_ci(tl, "/tmp/"))) {
                            Finding f;
                            f.rule_id = "LNX.SSH.PROXYCMD.001";
                            f.severity = "high";
                            f.confidence = "medium";
                            f.rationale = "SSH config ProxyCommand 含可疑命令: " + tl.substr(0, 150);
                            f.object_ref = cfg + ":" + std::to_string(lno);
                            f.advice_id = "ADVICE.SSHKEY.REVIEW.001";
                            ctx.add_finding(f);
                        }
                    });
                }
            }
            // 私钥存在性（仅文件名+哈希，绝不读内容进证据 payload）
            for (const char* kf : {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}) {
                std::string pk = home + "/.ssh/" + kf;
                if (!file_exists(pk)) continue;
                ReadResult pr = read_text_file(pk, 64 * 1024);
                if (!pr.ok) continue;
                Finding f;
                f.rule_id = "LNX.SSH.PRIVKEY.001";
                f.severity = "low";
                f.confidence = "high";
                f.rationale = "用户 " + name + " 存在私钥文件 " + kf +
                              "（仅记录存在与哈希；若为攻击者遗留需处置）";
                f.evidence_paths = {pk};
                f.advice_id = "ADVICE.SSHKEY.REVIEW.001";
                ctx.add_finding(f);
                Evidence e;
                e.source_kind = "file";
                e.source_path = pk;
                e.sha256 = pr.raw_sha256;
                e.payload = "(私钥内容不采集) size=" + std::to_string(pr.raw_size);
                e.limitations = {"隐私保护：仅存在性+哈希"};
                ctx.add_evidence(e);
            }
            // .ssh 下点开头隐藏密钥（玄机·行业攻防：/root/.ssh/.id_rsa.pub 藏公钥）
            for (const auto& hp : list_dir(home + "/.ssh", 100)) {
                std::string base = hp.substr(hp.find_last_of('/') + 1);
                if (base.empty() || base[0] != '.') continue;
                std::string bl = to_lower(base);
                bool keyish = ends_with(bl, ".pub") || ends_with(bl, ".keystore") ||
                              bl.find("authoriz") != std::string::npos ||
                              bl.find("id_rsa") != std::string::npos ||
                              bl.find("id_ed25519") != std::string::npos ||
                              bl.find("id_ecdsa") != std::string::npos;
                if (!keyish) continue;
                if (!seen_hidden.insert(hp).second) continue;
                Finding f;
                f.rule_id = "LNX.SSH.HIDDENKEY.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "用户 " + name + " 的 .ssh 下存在点开头隐藏密钥文件: " + base +
                              "（攻击者藏匿公钥/私钥的常见手法，需核实是否被 AuthorizedKeysFile 引用）";
                f.object_ref = hp;
                f.evidence_paths = {hp};
                f.advice_id = "ADVICE.SSHKEY.REVIEW.001";
                ctx.add_finding(f);
            }
        });
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L03 cron ----
void mod_cron(ModuleCtx& ctx) {
    std::vector<std::string> files;
    files.push_back("/etc/crontab");
    files.push_back("/etc/anacrontab");
    for (const auto& d : {"/etc/cron.d", "/etc/crontabs", "/var/spool/cron",
                          "/var/spool/cron/crontabs",
                          "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
                          "/etc/cron.monthly"})
        for (const auto& f : list_dir(d, 200))
            files.push_back(f);

    size_t followed = 0;
    for (const auto& f : files) {
        struct stat source_stat{};
        if (!stat(f.c_str(), &source_stat) && S_ISDIR(source_stat.st_mode)) continue;
        ReadResult r = read_source(ctx, f, false);
        if (!r.ok) continue;
        for_each_line(r.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            std::vector<std::string> refs = {f};
            int risk = persistence_risk(ctx, t, refs, followed);
            if (!risk) return;
            Finding fd;
            fd.rule_id = "LNX.PERSIST.CRON.001";
            fd.severity = risk >= 3 ? "high" : "medium";
            fd.confidence = risk >= 3 ? "high" : "medium";
            fd.rationale = "计划任务执行隐藏/临时路径或反弹/下载执行链: " + t.substr(0, 400);
            fd.evidence_paths = refs;
            fd.object_ref = f + ":" + std::to_string(no);
            fd.limitations = {"只读静态分析；引用脚本最多一层/64KiB/每模块64个；路径可疑不等于恶意"};
            fd.advice_id = "ADVICE.CRON.REVIEW.001";
            ctx.add_finding(fd);
        });
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L04 shell 持久化 ----
void mod_shell(ModuleCtx& ctx) {
    std::vector<std::string> files = {"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"};
    for (const auto& f : list_dir("/etc/profile.d", 100)) files.push_back(f);
    // 各用户配置
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    if (pw.ok) {
        for_each_line(pw.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            int seen = 0, p5 = 0, p6 = 0;
            for (int i = 0; i < static_cast<int>(t.size()); ++i) {
                if (t[i] == ':') { ++seen; if (seen == 5) p5 = i; if (seen == 6) { p6 = i; break; } }
            }
            if (seen < 6) return;
            std::string home = t.substr(p5 + 1, p6 - p5 - 1);
            if (home.empty() || home[0] != '/') return;
            for (const char* rc : {"/.profile", "/.bash_profile", "/.bash_login", "/.bashrc"})
                files.push_back(home + rc);
        });
    }
    std::set<std::string> seen_profile;
    for (const auto& f : files) {
        if (!seen_profile.insert(f).second) continue;
        ReadResult r = read_source(ctx, f, false);
        if (!r.ok) continue;
        for_each_line(r.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            bool suspicious = false;
            std::string why;
            if (starts_with(t, "PROMPT_COMMAND") &&
                (contains_ci(t, "curl") || contains_ci(t, "wget") || contains_ci(t, "base64") ||
                 contains_ci(t, "nc "))) {
                suspicious = true;
                why = "PROMPT_COMMAND 含网络/解码特征";
            } else if (profile_alias_is_hijack(t)) {
                suspicious = true;
                why = "alias 劫持了系统命令";
            } else if (contains_ci(t, "PATH=") &&
                       (t.find("/tmp") != std::string::npos ||
                        t.find("/dev/shm") != std::string::npos)) {
                suspicious = true;
                why = "PATH 引入临时目录";
            } else if (!match_tokens(t).empty() && !starts_with(t, "#")) {
                auto hits = match_tokens(t);
                // 常规合法行（如 PATH=/usr/bin）不误报：仅当命中高危险令牌
                for (auto& [tk, w] : hits) {
                    if (std::string(tk) == "/tmp/" || std::string(tk) == "/dev/shm" ||
                        std::string(tk) == "base64 -d" || std::string(tk) == "nc -e" ||
                        std::string(tk) == "python -c" || std::string(tk) == "perl -e" ||
                        std::string(tk) == "stratum+tcp" || std::string(tk) == "xmrig") {
                        suspicious = true;
                        why = std::string("特征: ") + tk + "(" + w + ")";
                        break;
                    }
                }
            }
            if (!suspicious) return;
            Finding fd;
            fd.rule_id = "LNX.PERSIST.PROFILE.001";
            fd.severity = "medium";
            fd.confidence = "medium";
            fd.rationale = "shell 配置含可疑行: " + why + "——个性化配置可能命中，需人工核对";
            fd.evidence_paths = {f};
            fd.object_ref = f + ":" + std::to_string(no);
            fd.limitations = {"静态解析，不执行不 source；动态拼接无法求值"};
            fd.advice_id = "ADVICE.PROFILE.REVIEW.001";
            ctx.add_finding(fd);
        });
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L05 preload ----
void mod_preload(ModuleCtx& ctx) {
    ReadResult r = read_source(ctx, "/etc/ld.so.preload", false);
    if (r.ok) {
        for_each_line(r.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            Finding f;
            f.rule_id = "LNX.PERSIST.PRELOAD.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "ld.so.preload 配置了预加载库: " + t +
                          "（监控/调试软件可能合法；库本体哈希见证据）";
            f.evidence_paths = {"/etc/ld.so.preload"};
            f.object_ref = "/etc/ld.so.preload:" + std::to_string(no);
            f.limitations = {"静态配置检查；不保证检出内核层隐藏"};
            f.advice_id = "ADVICE.PRELOAD.REVIEW.001";
            ctx.add_finding(f);
            if (file_exists(t)) {
                ReadResult lib = read_text_file(t, 8 * 1024 * 1024);
                if (lib.ok) {
                    Evidence e;
                    e.source_kind = "file";
                    e.source_path = t;
                    e.sha256 = lib.raw_sha256;
                    e.payload = "(库文件不落 payload) size=" + std::to_string(lib.raw_size);
                    ctx.add_evidence(e);
                }
            }
        });
    }
    ctx.note("LD_PRELOAD 进程环境变量采集未纳入 v1（隐私与噪声考量）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L06 hosts ----
void mod_hosts(ModuleCtx& ctx) {
    ReadResult r = read_source(ctx, "/etc/hosts", true);
    if (!r.ok) { ctx.set_status(ModuleStatus::PERMISSION_DENIED); return; }
    for_each_line(r.content, [&](int no, const std::string& line) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') return;
        std::istringstream is(t);
        std::string ip, name;
        if (!(is >> ip)) return;
        while (is >> name) {
            // 发行版默认本地条目（含 IPv6 本地名）不算映射
            if (name == "localhost" || name == "localhost.localdomain" ||
                starts_with(name, "ip6-")) continue;
            bool loopback = (ip == "127.0.0.1" || ip == "::1" || starts_with(ip, "127."));
            if (loopback) {
                // A7C9-W05 同构：回环绑定非常规名仍是线索
                Finding f;
                f.rule_id = "LNX.HOSTS.LOOPBACK.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "本机回环绑定非常规名: " + ip + " -> " + name +
                              "（本地测试/屏蔽常见；陌生域名需核实）";
                f.object_ref = "/etc/hosts:" + std::to_string(no);
                f.advice_id = "ADVICE.HOSTS.REVIEW.001";
                ctx.add_finding(f);
                continue;
            }
            if (starts_with(name, "localhost")) continue;
            static std::string hostname;
            static bool host_loaded = false;
            if (!host_loaded) {
                ReadResult hn = read_text_file("/etc/hostname", 256);
                if (hn.ok) hostname = trim(hn.content);
                host_loaded = true;
            }
            if (!hostname.empty() && name == hostname) continue;
            Finding f;
            f.rule_id = "LNX.HOSTS.MAP.001";
            f.severity = "low";
            f.confidence = "medium";
            f.rationale = "hosts 非默认映射: " + ip + " -> " + name +
                          "（内网授权映射常见；无基线时仅列证据，不武断定性）";
            f.evidence_paths = {"/etc/hosts"};
            f.object_ref = "/etc/hosts:" + std::to_string(no);
            f.advice_id = "ADVICE.HOSTS.REVIEW.001";
            ctx.add_finding(f);
        }
    });
    ctx.set_status(ModuleStatus::PASS);
}

// ---- L13 痕迹/内核模块 ----
void mod_trace(ModuleCtx& ctx) {
    // /proc/modules
    ctx.planned_source("/proc/modules");
    std::ifstream mods("/proc/modules");
    if (mods) {
        std::stringstream ss;
        ss << mods.rdbuf();
        std::string content = ss.str();
        Evidence e;
        e.source_kind = "proc";
        e.source_path = "/proc/modules";
        e.payload = content.substr(0, 64 * 1024);
        ctx.add_evidence(e);
        ctx.checked_source("/proc/modules");
        ctx.note("内核模块无基线，仅列证据供人工比对发行版清单");
    } else {
        ctx.omitted_source("/proc/modules", "不可读");
    }
    // 各用户 bash_history
    ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
    if (pw.ok) {
        std::set<std::string> seen_hist;
        for_each_line(pw.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            int seen = 0, p5 = 0, p6 = 0;
            for (int i = 0; i < static_cast<int>(t.size()); ++i) {
                if (t[i] == ':') { ++seen; if (seen == 5) p5 = i; if (seen == 6) { p6 = i; break; } }
            }
            if (seen < 6) return;
            std::string home = t.substr(p5 + 1, p6 - p5 - 1);
            std::string name = t.substr(0, t.find(':'));
            if (home.empty() || home[0] != '/') return;
            ReadResult r = read_source(ctx, home + "/.bash_history", false);
            if (!r.ok) return;
            for_each_line(r.content, [&](int no, const std::string& l) {
                if (!history_line_is_clue(l)) return;
                std::string href = home + "/.bash_history:" + std::to_string(no);
                if (!seen_hist.insert(href).second) return;
                Finding f;
                f.rule_id = "LNX.TRACE.HISTORY.001";
                f.severity = "medium";
                f.confidence = "low"; // 历史是线索非结论
                f.rationale = "用户 " + name + " 的 bash_history 含可疑命令: " + trim(l).substr(0, 120);
                f.evidence_paths = {home + "/.bash_history"};
                f.object_ref = home + "/.bash_history:" + std::to_string(no);
                f.limitations = {"历史为线索非结论；history 可能被清空/篡改"};
                f.advice_id = "ADVICE.PROFILE.REVIEW.001";
                ctx.add_finding(f);
            });
        });
    }
    ctx.note("wtmp/last 二进制解析未纳入 v1");
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

// ---- 注册（供 modules.cpp 汇合）----
void register_mods_a(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.ACC", "1.0.0", "linux", [](ModuleCtx& c) { mod_acc(c); }});
    mods.push_back({"LNX.SSH", "1.0.0", "linux", [](ModuleCtx& c) { mod_ssh(c); }});
    mods.push_back({"LNX.CRON", "1.0.0", "linux", [](ModuleCtx& c) { mod_cron(c); }});
    mods.push_back({"LNX.SHELL", "1.0.0", "linux", [](ModuleCtx& c) { mod_shell(c); }});
    mods.push_back({"LNX.PRELOAD", "1.0.0", "linux", [](ModuleCtx& c) { mod_preload(c); }});
    mods.push_back({"LNX.HOSTS", "1.0.0", "linux", [](ModuleCtx& c) { mod_hosts(c); }});
    mods.push_back({"LNX.TRACE", "1.0.0", "linux", [](ModuleCtx& c) { mod_trace(c); }});
}

} // namespace ctfir::lnx
