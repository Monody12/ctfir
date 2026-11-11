// Linux 痕迹模块族（v0.3 Phase2）：LNX.WEB / LNX.LOGINS(lastlog-wtmp) / ld.so.conf.d 注入
#include "lnx_common.hpp"

#include <cstring>
#include <ctime>
#include <map>

namespace ctfir::lnx {

namespace {

// webshell 静态特征判定（与 WIN.WEB 同口径）
static bool webshell_hit(const std::string& c, bool& strong) {
    bool exec_call = contains_ci(c, "eval(") || contains_ci(c, "assert(") ||
                     contains_ci(c, "system(") || contains_ci(c, "shell_exec") ||
                     contains_ci(c, "passthru(") || contains_ci(c, "exec(") ||
                     contains_ci(c, "Runtime.getRuntime().exec") || contains_ci(c, "ProcessBuilder");
    bool req_input = contains_ci(c, "$_POST") || contains_ci(c, "$_GET") ||
                     contains_ci(c, "$_REQUEST") || contains_ci(c, "Request[") ||
                     contains_ci(c, "request.getParameter");
    bool decode = contains_ci(c, "base64_decode") || contains_ci(c, "gzinflate") ||
                  contains_ci(c, "str_rot13");
    // 深化特征（免杀变形）
    bool var_var = c.find("$$") != std::string::npos;                   // 可变变量 $$x
    bool preg_e = contains_ci(c, "preg_replace") && contains_ci(c, "/e"); // /e 修饰符
    bool callfunc = contains_ci(c, "call_user_func") || contains_ci(c, "create_function");
    bool b64_file = contains_ci(c, "file_put_contents") && contains_ci(c, "base64");
    strong = exec_call && (req_input || decode);
    return strong || (var_var && exec_call) || (preg_e && exec_call) ||
           (callfunc && exec_call && req_input) || (b64_file && exec_call);
}

static void scan_web_dir(ModuleCtx& ctx, const std::string& dir, int depth, int& files, int& hits) {
    if (depth > 4 || files > 800 || ctx.expired()) return;
    for (const auto& p : list_dir(dir, 400)) {
        struct stat st{};
        if (lstat(p.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            scan_web_dir(ctx, p, depth + 1, files, hits);
            if (files > 800 || ctx.expired()) return;
            continue;
        }
        std::string low = to_lower(p);
        if (!(ends_with(low, ".php") || ends_with(low, ".phtml") || ends_with(low, ".jsp") ||
              ends_with(low, ".jspx") || ends_with(low, ".asp") || ends_with(low, ".aspx")))
            continue;
        if (++files > 800) return;
        ReadResult r = read_text_file(p, 512 * 1024);
        if (!r.ok) continue;
        bool strong = false;
        if (webshell_hit(r.content, strong)) {
            ++hits;
            Finding f;
            f.rule_id = "LNX.WEB.SHELL.001";
            f.severity = strong ? "high" : "medium";
            f.confidence = "medium";
            f.rationale = "疑似 webshell（静态特征）: " + p + "——命中≠定罪，需人工读文件并对照日志";
            f.object_ref = p;
            f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
            ctx.add_finding(f);
            Evidence e;
            e.source_kind = "file";
            e.source_path = p;
            e.sha256 = r.raw_sha256;
            e.payload = r.content.size() > 2048 ? r.content.substr(0, 2048) + "...[截断]" : r.content;
            ctx.add_evidence(e);
        }
    }
}

// ---- LNX.WEB ----
void mod_web(ModuleCtx& ctx) {
    // conf root 指令解析
    std::vector<std::string> confs = {"/etc/nginx/nginx.conf", "/etc/httpd/conf/httpd.conf",
                                      "/etc/apache2/apache2.conf"};
    for (const auto& d : {"/etc/nginx/conf.d", "/etc/nginx/sites-enabled",
                          "/etc/httpd/conf.d", "/etc/apache2/sites-enabled"})
        for (const auto& f : list_dir(d, 100)) confs.push_back(f);
    std::vector<std::string> roots;
    for (const auto& cf : confs) {
        ReadResult r = read_source(ctx, cf, false);
        if (!r.ok) continue;
        for_each_line(r.content, [&](int, const std::string& line) {
            std::string t = trim(line);
            if (starts_with(t, "root ") || starts_with(t, "DocumentRoot ")) {
                std::string v = trim(t.substr(t.find(' ') + 1));
                while (!v.empty() && (v.back() == ';' || v.back() == '"')) v.pop_back();
                if (!v.empty() && v[0] == '/') roots.push_back(v);
            }
        });
    }
    for (const char* d : {"/var/www", "/var/www/html", "/usr/share/nginx/html",
                          "/home/www", "/data/www", "/opt/www"})
        roots.push_back(d);
    // 去重扫描
    std::set<std::string> seen;
    std::string summary;
    int tot_files = 0, tot_hits = 0;
    for (const auto& root : roots) {
        if (!seen.insert(root).second) continue;
        struct stat st{};
        if (lstat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        ctx.planned_source(root);
        int files = 0, hits = 0;
        scan_web_dir(ctx, root, 0, files, hits);
        tot_files += files;
        tot_hits += hits;
        summary += root + " (script_files=" + std::to_string(files) + " hits=" + std::to_string(hits) + ")\n";
        ctx.checked_source(root);
    }
    if (summary.empty()) ctx.note("未发现 web 根（nginx/apache 未装或非标路径）");
    // access 日志（common/combined：首字段 IP，引号内 METHOD）
    for (const char* lg : {"/var/log/nginx/access.log", "/var/log/httpd/access_log",
                           "/var/log/apache2/access.log"}) {
        ctx.planned_source(lg);
        ReadResult r = read_text_file(lg, 16 * 1024 * 1024);
        if (!r.ok) { ctx.checked_source(std::string(lg) + " [miss]"); continue; }
        std::map<std::string, int> post_ip;
        int posts = 0;
        for_each_line(r.content, [&](int, const std::string& line) {
            std::istringstream is(line);
            std::string ip, junk, method;
            if (!(is >> ip >> junk)) return;
            // combined: IP - user [time] "METHOD ..."
            size_t q = line.find('"');
            if (q == std::string::npos) return;
            std::istringstream rq(line.substr(q + 1));
            rq >> method;
            if (method == "POST") { ++posts; ++post_ip[ip]; }
        });
        if (posts > 0) {
            std::string top;
            for (const auto& [ip, cnt] : post_ip) top += ip + "×" + std::to_string(cnt) + " ";
            Evidence le;
            le.source_kind = "file";
            le.source_path = lg;
            le.sha256 = r.raw_sha256;
            le.payload = "POST=" + std::to_string(posts) + "\ntop_ip: " + top;
            std::string ev_id = ctx.add_evidence(le);
            ctx.checked_source(lg);
            if (posts >= 50) {
                Finding f;
                f.rule_id = "LNX.WEB.LOGPOST.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "web 日志 POST 集中（" + std::to_string(posts) +
                              " 次）：webshell 交互/上传线索；Top IP 见证据";
                f.object_ref = lg;
                f.evidence_ids = {ev_id};
                f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    }
    Evidence e;
    e.source_kind = "dir";
    e.source_path = "LNX.WEB 汇总";
    e.payload = summary.empty() ? "(none)" : summary;
    ctx.add_evidence(e);
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.LOGINS：lastlog/wtmp 登录时间线 ----
void mod_logins(ModuleCtx& ctx) {
    // lastlog：struct { int32 time; char line[32]; char host[256]; } = 292B（glibc x86_64）
    {
        ctx.planned_source("/var/log/lastlog");
        FILE* f = fopen("/var/log/lastlog", "rb");
        if (f) {
            // uid→name 映射
            std::map<int, std::string> names;
            ReadResult pw = read_text_file("/etc/passwd", 1024 * 1024);
            if (pw.ok) {
                for_each_line(pw.content, [&](int, const std::string& line) {
                    int p1 = -1, p2 = -1, seen = 0;
                    for (int i = 0; i < (int)line.size(); ++i)
                        if (line[i] == ':') { if (++seen == 1) p1 = i; if (seen == 3) { p2 = i; break; } }
                    if (p1 > 0 && p2 > 0)
                        names[std::atoi(line.substr(p1 + 1, p2 - p1 - 1).c_str())] = line.substr(0, p1);
                });
            }
            static const size_t REC = 292;
            std::string rows;
            int n = 0;
            for (int uid = 0; uid <= 60000; ++uid) {
                struct LastLog { int32_t t; char line[32]; char host[256]; } ll{};
                if (fseek(f, (long)uid * (long)REC, SEEK_SET) != 0) break;
                if (fread(&ll, 1, REC, f) != REC) break;
                if (ll.t == 0) continue;
                time_t tt = ll.t;
                char tb[24];
                strftime(tb, sizeof(tb), "%Y-%m-%d %H:%M", localtime(&tt));
                std::string nm = names.count(uid) ? names[uid] : ("uid" + std::to_string(uid));
                rows += std::string(tb) + " " + nm + " line=" + std::string(ll.line) + " host=" + std::string(ll.host) + "\n";
                if (++n > 100) break;
            }
            fclose(f);
            Evidence e;
            e.source_kind = "file";
            e.source_path = "/var/log/lastlog";
            e.payload = rows.empty() ? "(无登录记录)" : rows;
            ctx.add_evidence(e);
            ctx.checked_source("/var/log/lastlog");
            if (!rows.empty())
                ctx.note("lastlog 记录最后登录事实；异常 host/时间需人工核对");
        } else {
            ctx.checked_source("/var/log/lastlog [miss]");
        }
    }
    // wtmp：utmp 384B（x86_64）；USER_PROCESS=7
    {
        ctx.planned_source("/var/log/wtmp");
        FILE* f = fopen("/var/log/wtmp", "rb");
        if (f) {
            struct WTmp {
                int16_t type; int16_t pad; int32_t pid;
                char line[32]; char id[4]; char user[32];
                char host[256]; int32_t session;
                int32_t tv_sec; int32_t tv_usec;
                int32_t addr[4]; char unused[20];
            };
            std::string rows;
            int n = 0;
            WTmp u{};
            while (fread(&u, 1, sizeof(u), f) == sizeof(u)) {
                if (u.type == 7 && n < 300) { // USER_PROCESS
                    time_t tt = u.tv_sec;
                    char tb[24];
                    strftime(tb, sizeof(tb), "%Y-%m-%d %H:%M", localtime(&tt));
                    rows += std::string(tb) + " user=" + std::string(u.user) + " tty=" + std::string(u.line) +
                            " host=" + std::string(u.host) + "\n";
                    ++n;
                }
            }
            fclose(f);
            Evidence e;
            e.source_kind = "file";
            e.source_path = "/var/log/wtmp";
            e.payload = rows.empty() ? "(无记录)" : rows;
            ctx.add_evidence(e);
            ctx.checked_source("/var/log/wtmp");
            if (!rows.empty())
                ctx.note("wtmp 登录时间线（最近在后；轮转历史不含）");
        } else {
            ctx.checked_source("/var/log/wtmp [miss]");
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.LDSO：ld.so.conf.d 注入 ----
void mod_ldso(ModuleCtx& ctx) {
    for (const auto& p : list_dir("/etc/ld.so.conf.d", 100)) {
        ReadResult r = read_source(ctx, p, false);
        if (!r.ok) continue;
        for_each_line(r.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') return;
            if (starts_with(t, "/usr/lib") || starts_with(t, "/lib") ||
                t == "/usr/local/lib") return;
            Finding f;
            f.rule_id = "LNX.LDSO.INJECT.001";
            f.severity = "medium";
            f.confidence = "medium";
            f.rationale = "动态库搜索路径指向非常规目录: " + t + "（" + p + " 第 " + std::to_string(no) +
                          " 行）——库投递/劫持常见手法，需核实目录内容";
            f.object_ref = p + ":" + std::to_string(no);
            f.advice_id = "ADVICE.PRELOAD.REVIEW.001";
            ctx.add_finding(f);
        });
    }
    // .htaccess / .user.ini 后门检查
    for (const char* root : {"/var/www/html", "/var/www", "/usr/share/nginx/html"}) {
        for (const char* fn : {".htaccess", ".user.ini"}) {
            std::string p = std::string(root) + "/" + fn;
            ReadResult r = read_text_file(p, 64 * 1024);
            if (!r.ok) continue;
            for_each_line(r.content, [&](int no, const std::string& l) {
                std::string t = trim(l);
                if (t.empty() || t[0] == '#') return;
                if (contains_ci(t, "auto_prepend_file") || contains_ci(t, "auto_append_file") ||
                    contains_ci(t, "AddType application/x-httpd-php") ||
                    contains_ci(t, "php_value auto_prepend_file")) {
                    Finding f;
                    f.rule_id = "LNX.WEB.CONFIGBACKDOOR.001";
                    f.severity = "high";
                    f.confidence = "medium";
                    f.rationale = fn + std::string(" 后门（auto_prepend/类型劫持）: ") + t.substr(0, 150);
                    f.object_ref = p + ":" + std::to_string(no);
                    f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                    ctx.add_finding(f);
                }
            });
        }
    }
    // btmp 暴力破解计数
    {
        FILE* bf = fopen("/var/log/btmp", "rb");
        if (bf) {
            fseek(bf, 0, SEEK_END);
            long sz = ftell(bf);
            fclose(bf);
            int entries = static_cast<int>(sz / 384); // utmp 384B 结构
            if (entries > 100) {
                Finding f;
                f.rule_id = "LNX.LOG.BTMP.001";
                f.severity = "medium";
                f.confidence = "medium";
                f.rationale = "btmp 登录失败记录 " + std::to_string(entries) +
                              " 条（大量爆破痕迹；用 lastb 命令查看详情）";
                f.object_ref = "/var/log/btmp";
                f.advice_id = "ADVICE.EVENTLOG.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_d(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"LNX.WEB", "1.0.0", "linux", [](ModuleCtx& c) { mod_web(c); }});
    mods.push_back({"LNX.LOGINS", "1.0.0", "linux", [](ModuleCtx& c) { mod_logins(c); }});
    mods.push_back({"LNX.LDSO", "1.0.0", "linux", [](ModuleCtx& c) { mod_ldso(c); }});
}

} // namespace ctfir::lnx
