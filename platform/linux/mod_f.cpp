// 中间件与服务核查模块族（v0.4）：Redis / MySQL / PHP / Tomcat / Nginx 危险配置，
// web 根备份文件泄露。对照决赛指南"数据库与中间件安全配置核查"考点。
#include "lnx_common.hpp"

#include <cstring>

namespace ctfir::lnx {

namespace {

// conf 解析助手：key = value / key value / <key>（无值开关）
struct ConfLine { std::string key; std::string val; int no; };
static std::vector<ConfLine> parse_conf(const std::string& content) {
    std::vector<ConfLine> out;
    for_each_line(content, [&](int no, const std::string& line) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#' || t[0] == ';' || t[0] == '[') return;
        if (t.back() == ';') t.pop_back();
        size_t sp = t.find_first_of(" \t=");
        if (sp == std::string::npos) { out.push_back({to_lower(t), "", no}); return; }
        std::string k = to_lower(trim(t.substr(0, sp)));
        std::string v = trim(t.substr(sp + 1));
        while (!v.empty() && (v.front() == '=' || v.front() == ' ')) v.erase(v.begin());
        if (!v.empty() && v.front() == '"') v = v.substr(1, v.size() - 2);
        out.push_back({k, v, no});
    });
    return out;
}

static void finding_kv(ModuleCtx& ctx, const char* rule, const char* sev, const std::string& file,
                       const ConfLine& c, const std::string& msg) {
    Finding f;
    f.rule_id = rule;
    f.severity = sev;
    f.confidence = "high";
    f.rationale = msg + "（" + file + " 第 " + std::to_string(c.no) + " 行: " + c.key +
                  (c.val.empty() ? "" : " = " + c.val) + "）";
    f.object_ref = file + ":" + std::to_string(c.no);
    f.advice_id = "ADVICE.HARDEN.001";
    ctx.add_finding(f);
}

// ---- MID.REDIS：未授权访问/危险配置 ----
void mod_redis(ModuleCtx& ctx) {
    std::vector<std::string> confs = {"/etc/redis/redis.conf", "/etc/redis.conf",
                                      "/usr/local/redis/redis.conf"};
    bool running = false;
    // 进程判定
    for (const auto& p : list_dir("/proc", 20000)) {
        std::string base = p.substr(p.find_last_of('/') + 1);
        if (base.empty() || base[0] < '0' || base[0] > '9') continue;
        ReadResult c = read_text_file(p + "/cmdline", 1024);
        if (c.ok && contains_ci(c.content, "redis-server")) { running = true; break; }
    }
    if (!running) { ctx.note("未发现 redis-server 进程"); }
    for (const auto& cf : confs) {
        ReadResult r = read_source(ctx, cf, false);
        if (!r.ok) continue;
        bool has_pass = false, bind_all = false;
        for (const auto& c : parse_conf(r.content)) {
            if (c.key == "requirepass" && !c.val.empty()) has_pass = true;
            if (c.key == "bind" && (c.val == "0.0.0.0" || c.val.empty())) bind_all = true;
            if (c.key == "protected-mode" && c.val == "no") {
                finding_kv(ctx, "MID.REDIS.PROTMODE.001", "high", cf, c,
                           "Redis protected-mode 已关闭");
            }
        }
        if (!has_pass) {
            Finding f;
            f.rule_id = "MID.REDIS.NOPASS.001";
            f.severity = "high";
            f.confidence = "medium";
            f.rationale = "Redis 配置未设置 requirepass" +
                          std::string(bind_all ? " 且监听所有网卡" : "") +
                          "——未授权访问可写 crontab/SSH key 拿壳（CTF 高频链）";
            f.object_ref = cf;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        } else if (bind_all) {
            Finding f;
            f.rule_id = "MID.REDIS.BINDALL.001";
            f.severity = "medium";
            f.confidence = "high";
            f.rationale = "Redis 设置了口令但监听所有网卡——暴露面扩大";
            f.object_ref = cf;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- MID.MYSQL：危险配置 + 日志定位 ----
void mod_mysql(ModuleCtx& ctx) {
    std::vector<std::string> confs = {"/etc/my.cnf", "/etc/mysql/my.cnf",
                                      "/etc/mysql/mysql.conf.d/mysqld.cnf"};
    bool running = false;
    for (const auto& p : list_dir("/proc", 20000)) {
        std::string base = p.substr(p.find_last_of('/') + 1);
        if (base.empty() || base[0] < '0' || base[0] > '9') continue;
        ReadResult c = read_text_file(p + "/cmdline", 1024);
        if (c.ok && (contains_ci(c.content, "mysqld") || contains_ci(c.content, "mariadbd"))) {
            running = true; break;
        }
    }
    if (!running) { ctx.note("未发现 mysqld 进程"); }
    for (const auto& cf : confs) {
        ReadResult r = read_source(ctx, cf, false);
        if (!r.ok) continue;
        for (const auto& c : parse_conf(r.content)) {
            if (c.key == "skip-grant-tables") {
                finding_kv(ctx, "MID.MYSQL.SKIPGRANT.001", "high", cf, c,
                           "MySQL skip-grant-tables（免密登录所有账户）");
            } else if (c.key == "local-infile" && c.val == "1") {
                finding_kv(ctx, "MID.MYSQL.LOCALINFILE.001", "medium", cf, c,
                           "MySQL local-infile 开启（LOAD DATA LOCAL 可读客户端文件）");
            } else if (c.key == "bind-address" && c.val == "0.0.0.0") {
                finding_kv(ctx, "MID.MYSQL.BINDALL.001", "low", cf, c,
                           "MySQL 监听所有网卡（暴露面）");
            } else if (c.key == "general_log" && c.val == "1") {
                finding_kv(ctx, "MID.MYSQL.GENLOG.001", "low", cf, c,
                           "MySQL general_log 开启（含全量查询语句，审计/取证金矿，建议核对日志文件）");
            }
        }
    }
    // general_log 内容取证：攻击者常 SELECT ... INTO OUTFILE 写 webshell（日志写马痕迹）
    {
        std::vector<std::string> glogs;
        // 配置里可能指定 general_log_file
        for (const auto& cf : confs) {
            ReadResult r = read_text_file(cf, 512 * 1024);
            if (!r.ok) continue;
            for (const auto& c : parse_conf(r.content)) {
                if (c.key == "general_log_file" && !c.val.empty()) {
                    std::string v = c.val;
                    if (v.find('/') == std::string::npos)
                        v = "/var/lib/mysql/" + v; // 相对名默认落在 datadir
                    glogs.push_back(v);
                }
            }
        }
        // 常见默认路径兜底
        for (const char* p : {"/var/log/mysql/mysql.log", "/var/log/mysql/general.log"}) {
            if (file_exists(p)) glogs.push_back(p);
        }
        for (const auto& d : list_dir("/var/lib/mysql", 100)) {
            if (ends_with(to_lower(d), ".log")) glogs.push_back(d);
        }
        int scanned = 0;
        for (const auto& gl : glogs) {
            if (scanned >= 3) break; // 最多核对 3 个日志文件
            ReadResult r = read_text_file(gl, 16 * 1024 * 1024);
            if (!r.ok) continue;
            ++scanned;
            int outfile_hits = 0;
            for_each_line(r.content, [&](int, const std::string& line) {
                std::string low = to_lower(line);
                if ((low.find("into outfile") != std::string::npos ||
                     low.find("into dumpfile") != std::string::npos) &&
                    (low.find(".php") != std::string::npos ||
                     low.find(".jsp") != std::string::npos ||
                     low.find("tmp") != std::string::npos ||
                     low.find("var/www") != std::string::npos)) {
                    ++outfile_hits;
                    if (outfile_hits <= 3) {
                        Finding f;
                        f.rule_id = "MID.MYSQL.LOGSHELL.001";
                        f.severity = "high";
                        f.confidence = "medium";
                        f.rationale = "MySQL general_log 中发现 INTO OUTFILE/DUMPFILE 写文件语句: " +
                                      line.substr(0, 180) + "（日志写马/UDF 提权痕迹）";
                        f.object_ref = gl;
                        f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                        ctx.add_finding(f);
                    }
                }
            });
        }
        if (scanned > 0) ctx.checked_source("MySQL general_log 内容取证（" + std::to_string(scanned) + " 文件）");
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- MID.PHP：php.ini 危险项 + phpinfo 文件 ----
void mod_php(ModuleCtx& ctx) {
    std::vector<std::string> inis;
    for (const auto& d : list_dir("/etc/php", 20)) {
        // /etc/php/<ver>/{apache2,cgi,cli,fpm}/php.ini
        for (const auto& s : list_dir(d, 20)) {
            std::string cand = s + "/php.ini";
            if (file_exists(cand)) inis.push_back(cand);
        }
    }
    for (const char* p : {"/etc/php.ini", "/usr/local/php/etc/php.ini",
                          "/etc/php5/apache2/php.ini", "/etc/php7/apache2/php.ini"})
        if (file_exists(p)) inis.push_back(p);
    for (const auto& ini : inis) {
        ReadResult r = read_source(ctx, ini, false);
        if (!r.ok) continue;
        for (const auto& c : parse_conf(r.content)) {
            if (c.key == "allow_url_include" && c.val == "on")
                finding_kv(ctx, "MID.PHP.URLINCLUDE.001", "high", ini, c,
                           "PHP allow_url_include=On（远程文件包含）");
            else if (c.key == "display_errors" && c.val == "on")
                finding_kv(ctx, "MID.PHP.DISERR.001", "low", ini, c,
                           "PHP display_errors=On（报错信息泄露）");
            else if (c.key == "expose_php" && c.val == "on")
                finding_kv(ctx, "MID.PHP.EXPOSE.001", "low", ini, c,
                           "PHP expose_php=On（版本指纹泄露）");
        }
    }
    // web 根下 phpinfo/备份文件（CTF 高频）
    for (const char* root : {"/var/www/html", "/var/www", "/usr/share/nginx/html"}) {
        for (const auto& p : list_dir(root, 300)) {
            std::string low = to_lower(p);
            if (low.find("phpinfo") != std::string::npos && ends_with(low, ".php")) {
                Finding f;
                f.rule_id = "MID.PHP.PHPINFO.001";
                f.severity = "medium";
                f.confidence = "high";
                f.rationale = "web 根下存在 phpinfo 文件: " + p + "（敏感信息泄露，比赛常见送分/切入点）";
                f.object_ref = p;
                f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                ctx.add_finding(f);
            }
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- MID.BACKUP：web 根备份/数据库文件/敏感凭据泄露 ----
void mod_backup(ModuleCtx& ctx) {
    for (const char* root : {"/var/www/html", "/var/www", "/usr/share/nginx/html"}) {
        for (const auto& p : list_dir(root, 300)) {
            std::string low = to_lower(p);
            std::string base = p.substr(p.find_last_of('/') + 1);
            // .git 目录（源码仓库泄露，CTF 高频信息泄露点）
            if (base == ".git") {
                Finding f;
                f.rule_id = "MID.WEB.GITLEAK.001";
                f.severity = "high";
                f.confidence = "high";
                f.rationale = "web 根下存在 .git 目录（源码/历史提交可被整站拉取，信息泄露）";
                f.object_ref = p + "/";
                f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                ctx.add_finding(f);
                continue;
            }
            bool risky = ends_with(low, ".sql") || ends_with(low, ".bak") ||
                         ends_with(low, ".sql.gz") || ends_with(low, ".zip") ||
                         ends_with(low, ".tar.gz") || ends_with(low, ".rar") ||
                         ends_with(low, ".swp") || ends_with(low, ".old");
            // 敏感凭据/密钥文件（.env 配置、私钥）
            bool creds = base == ".env" || ends_with(low, ".env") ||
                         ends_with(low, ".pem") || ends_with(low, ".key") ||
                         base == "id_rsa" || base == ".git-credentials" ||
                         base == ".htpasswd";
            if (!risky && !creds) continue;
            Finding f;
            f.rule_id = creds ? "MID.WEB.CREDS.001" : "MID.WEB.BACKUP.001";
            f.severity = creds ? "high" : "medium";
            f.confidence = "medium";
            f.rationale = creds
                ? "web 根下存在敏感凭据/密钥文件: " + p + "（数据库口令/API 密钥/私钥泄露）"
                : "web 根下存在备份/导出文件: " + p + "（源码或数据库泄露，可直接下载）";
            f.object_ref = p;
            f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- LNX.BASE.DROPRIGHT：中间件降权检查（个人赛"降权运行"考点）----
void mod_dropright(ModuleCtx& ctx) {
    // 两段式判定，避免 Apache/nginx "master root + worker 降权"标准架构误报：
    // - mysqld/redis/php-fpm/java 以 root 运行 → 直接报（这些必须降权）
    // - nginx/httpd/apache2 → 仅当该名字"所有实例都是 root"（worker 也没降权）才报
    static const char* mw_never_root[] = {"mysqld", "mariadbd", "redis-server", "php-fpm", "java"};
    static const char* mw_master_root[] = {"nginx", "httpd", "apache2"};
    struct ProcInfo { std::string pid; std::string name; int uid; };
    std::vector<ProcInfo> procs;
    for (const auto& p : list_dir("/proc", 20000)) {
        std::string base = p.substr(p.find_last_of('/') + 1);
        if (base.empty() || base[0] < '0' || base[0] > '9') continue;
        if (ctx.expired()) break;
        ReadResult cmd = read_text_file(p + "/cmdline", 512);
        if (!cmd.ok || cmd.content.empty()) continue;
        std::string argv0 = cmd.content.substr(0, cmd.content.find('\0'));
        size_t slash = argv0.find_last_of('/');
        std::string pname = slash == std::string::npos ? argv0 : argv0.substr(slash + 1);
        bool is_mw = false;
        for (const char* mw : mw_never_root)
            if (pname == mw || pname.find(mw) == 0) { is_mw = true; break; }
        if (!is_mw)
            for (const char* mw : mw_master_root)
                if (pname == mw || pname.find(mw) == 0) { is_mw = true; break; }
        if (!is_mw) continue;
        ReadResult st = read_text_file(p + "/status", 8 * 1024);
        if (!st.ok) continue;
        int uid = -1;
        for_each_line(st.content, [&](int, const std::string& line) {
            if (uid >= 0) return;
            if (starts_with(line, "Uid:")) {
                std::istringstream is(line.substr(4));
                is >> uid; // 第一个字段 = real uid
            }
        });
        if (uid < 0) continue;
        procs.push_back({base, pname, uid});
    }
    int flagged = 0;
    for (const auto& pr : procs) {
        bool never_root = false;
        for (const char* mw : mw_never_root)
            if (pr.name == mw || pr.name.find(mw) == 0) { never_root = true; break; }
        bool should_flag;
        if (never_root) {
            should_flag = (pr.uid == 0);
        } else {
            // master-root 组：该名字存在任一非 root 实例 → 架构正常，不报
            bool has_dropped = false;
            for (const auto& other : procs)
                if (other.name == pr.name && other.uid != 0) { has_dropped = true; break; }
            should_flag = (pr.uid == 0 && !has_dropped);
        }
        if (should_flag && flagged < 5) {
            ++flagged;
            Finding f;
            f.rule_id = "LNX.BASE.DROPRIGHT.001";
            f.severity = "medium";
            f.confidence = "high";
            f.rationale = "中间件进程以 root 运行（违背降权原则，被攻破即直接获得 root）: " +
                          pr.name + "（PID " + pr.pid + "）";
            f.object_ref = "PID " + pr.pid;
            f.advice_id = "ADVICE.HARDEN.001";
            ctx.add_finding(f);
        }
    }
    ctx.note("中间件降权检查：mysqld/redis/php-fpm root 即报；nginx/httpd 仅当 worker 也未降权才报（master-root 属标准架构）");
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_f(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"MID.REDIS", "1.0.0", "linux", [](ModuleCtx& c) { mod_redis(c); }});
    mods.push_back({"MID.MYSQL", "1.0.0", "linux", [](ModuleCtx& c) { mod_mysql(c); }});
    mods.push_back({"MID.PHP", "1.0.0", "linux", [](ModuleCtx& c) { mod_php(c); }});
    mods.push_back({"MID.BACKUP", "1.0.0", "linux", [](ModuleCtx& c) { mod_backup(c); }});
    mods.push_back({"LNX.BASE.DROPRIGHT", "1.0.0", "linux", [](ModuleCtx& c) { mod_dropright(c); }});
}

} // namespace ctfir::lnx
