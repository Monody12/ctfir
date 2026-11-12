#include "test_macros.hpp"
#include "core/triage.hpp"
#include "core/display_action.hpp"
#include "core/report.hpp"
#include "core/advice.hpp"
#include "core/util.hpp"

using namespace ctfir;

static Finding mk(const char* rid, const char* obj, const char* sev = "high",
                  const char* rationale = "r", const char* advice = "") {
    Finding f;
    f.rule_id = rid;
    f.object_ref = obj;
    f.severity = sev;
    f.confidence = "high";
    f.rationale = rationale;
    f.advice_id = advice;
    f.finding_id = "F1";
    return f;
}

CTFIR_TEST(triage_jw2026_buckets) {
    CHECK_EQ(bucket_of("WIN.ACC.DOLLAR.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.ACC.GUESTADMIN.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AUTORUN.IFEO.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.TASK.SUSPECT.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.PORTPROXY.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.HOSTS.MAP.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.FILES.DOUBLEEXT.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.FILES.ADS.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.BASE.UAC.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.BASE.BLANKPWD.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.AUDIT.DISABLED.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.EVT.ACC.CREATE.001"), Bucket::Trace);
    CHECK_EQ(bucket_of("WIN.WEB.LOGATTACK.001"), Bucket::Trace);
    CHECK_EQ(bucket_of("LNX.WEB.SHELL.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("MID.MYSQL.UDF.001"), Bucket::Web);
    CHECK_EQ(bucket_of("WIN.ACC.INVENTORY.001"), Bucket::Inventory);
    CHECK_EQ(bucket_of("WIN.TASK.FACT.001"), Bucket::Inventory);
    CHECK_EQ(bucket_of("WIN.FILES.RECENT.001"), Bucket::Inventory);
    CHECK_EQ(bucket_of("X.UNKNOWN.001"), Bucket::Trace);
}

CTFIR_TEST(triage_titles_and_visibility) {
    Finding dollar = mk("WIN.ACC.DOLLAR.001", "NetUserEnum:ctfir-marker$");
    Triage t = triage_of(dollar);
    CHECK(t.title_zh.find("美元") != std::string::npos);
    CHECK(t.default_visible);

    Finding inv = mk("WIN.ACC.INVENTORY.001", "NetUserEnum", "info");
    CHECK(!triage_of(inv).default_visible);
    CHECK(!finding_visible(inv, ViewPreset::Personal, "all", "all", ""));
    CHECK(finding_visible(inv, ViewPreset::All, "all", "all", ""));
    CHECK(finding_visible(dollar, ViewPreset::Personal, "all", "all", "美元"));
    CHECK(!finding_visible(dollar, ViewPreset::Personal, "all", "low", ""));
}

CTFIR_TEST(triage_sort_inventory_last) {
    std::vector<Finding> fds;
    fds.push_back(mk("WIN.ACC.INVENTORY.001", "x", "info"));
    fds.push_back(mk("WIN.ACC.DOLLAR.001", "NetUserEnum:h$", "medium"));
    fds.push_back(mk("WIN.BASE.UAC.001", "EnableLUA", "high"));
    auto idx = sorted_finding_indices(fds);
    CHECK_EQ(idx.size(), static_cast<size_t>(3));
    CHECK_EQ(fds[idx[0]].rule_id, std::string("WIN.ACC.DOLLAR.001"));
    CHECK_EQ(fds[idx[1]].rule_id, std::string("WIN.BASE.UAC.001"));
    CHECK_EQ(fds[idx[2]].rule_id, std::string("WIN.ACC.INVENTORY.001"));
}

CTFIR_TEST(display_action_filled_commands) {
    auto d = display_action(mk("WIN.ACC.DOLLAR.001", "NetUserEnum:ctfir-marker$", "medium",
                               "存在 $ 账户", "ADVICE.ACC.REVIEW.001"));
    CHECK(d.command.find("ctfir-marker$") != std::string::npos);
    CHECK(d.command.find("<账户名>") == std::string::npos);
    CHECK(d.command.find("net user") != std::string::npos);

    auto ifeo = display_action(mk("WIN.AUTORUN.IFEO.001", "IFEO\\ctfir-marker-ifeo.exe"));
    CHECK(ifeo.command.find("ctfir-marker-ifeo.exe") != std::string::npos);
    CHECK(ifeo.command.find("Debugger") != std::string::npos);
    CHECK(!ifeo.contest_note.empty());

    auto ads = display_action(mk("WIN.FILES.ADS.001",
        "C:\\Users\\Administrator\\Desktop\\note.txt:hidden.exe:$DATA"));
    CHECK(ads.command.find("powershell") == std::string::npos);
    CHECK(ads.command.find("del ") != std::string::npos);
    CHECK(ads.command.find("hidden.exe") != std::string::npos);

    auto auto_logon = display_action(mk("WIN.BASE.AUTOLOGON.001", "Winlogon\\AutoAdminLogon"));
    CHECK(auto_logon.command.find("AutoAdminLogon") != std::string::npos);
    CHECK(auto_logon.command.find("DefaultPassword") != std::string::npos);

    Finding sh = mk("WIN.SHARE.NONDEFAULT.001", "Shares", "low",
                    "非默认共享存在:\nctfir-marker \xE2\x86\x92 C:\\Windows\\Temp\\ctfir-marker-share");
    auto share = display_action(sh);
    CHECK(share.command.find("ctfir-marker") != std::string::npos);
    CHECK(share.command.find("net share") != std::string::npos);

    auto pp = display_action(mk("WIN.PORTPROXY.001", "PortProxy\\v4tov4\\tcp\\0.0.0.0/13389"));
    CHECK(pp.command.find("netsh") != std::string::npos);
    CHECK(pp.command.find("13389") != std::string::npos);
    CHECK(pp.command.find("0.0.0.0") != std::string::npos);

    auto start = display_action(mk("WIN.AUTORUN.SUSPECT.001",
        "C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ctfir-marker.vbs"));
    CHECK(start.command.find("del /f") != std::string::npos);
    CHECK(start.command.find("ctfir-marker.vbs") != std::string::npos);

    Finding cron;
    cron.rule_id = "LNX.PERSIST.CRON.001";
    cron.object_ref = "/etc/crontab:12";
    cron.severity = "high";
    auto c = display_action(cron);
    CHECK(c.command.find("/etc/crontab") != std::string::npos);
    CHECK(c.command.find("12") != std::string::npos);
    CHECK(c.command.find("sed") != std::string::npos);

    auto inv = display_action(mk("WIN.ACC.INVENTORY.001", "NetUserEnum", "info"));
    CHECK(inv.command.find("无需删除") != std::string::npos);
}

CTFIR_TEST(instantiate_advice_replaces_placeholder) {
    Finding f = mk("WIN.ACC.DOLLAR.001", "NetUserEnum:ctfir-marker$", "medium",
                   "r", "ADVICE.ACC.REVIEW.001");
    std::string t = instantiate_advice(f);
    CHECK(t.find("ctfir-marker$") != std::string::npos);
    CHECK(t.find("一条命令") != std::string::npos);
}

CTFIR_TEST(triage_ms_activesetup_inventory) {
    Finding ms = mk("WIN.BASE.ACTIVESETUP.001",
                    "ActiveSetup\\{6BF52A52-394A-11d3-B153-00C04F79FAA6}");
    CHECK_EQ(bucket_of(ms), Bucket::Inventory);
    CHECK(!triage_of(ms).default_visible);
    Finding custom = mk("WIN.BASE.ACTIVESETUP.001",
                        "ActiveSetup\\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}");
    CHECK_EQ(bucket_of(custom), Bucket::Clear);
    CHECK(triage_of(custom).default_visible);
}

CTFIR_TEST(html_checklist_and_xss) {
    ScanSession s;
    s.session_id = "t";
    s.tool_version = kToolVersion;
    s.os_name = "Windows";
    Finding f = mk("WIN.ACC.DOLLAR.001", "NetUserEnum:ctfir-marker$", "high",
                   "非root <script>alert(1)</script>\x00enc", "ADVICE.ACC.REVIEW.001");
    f.finding_id = "F-xss";
    std::vector<Finding> fds = {f, mk("WIN.ACC.INVENTORY.001", "NetUserEnum", "info", "清单")};
    fds[1].finding_id = "F-inv";
    auto adv = advices_for(fds);
    std::string html = build_html_report(s, {}, fds, adv, "2026-11-12 12:00:00");
    CHECK(html.find("处置清单") != std::string::npos);
    CHECK(html.find("美元号") != std::string::npos);
    CHECK(html.find("ctfir-marker$") != std::string::npos);
    CHECK(html.find("<script>alert(1)</script>") == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
    CHECK(html.find('\0') == std::string::npos);
    CHECK(html.find("http://") == std::string::npos);
    CHECK(html.find("https://") == std::string::npos);
    CHECK(html.find("onclick=\"setCat(") != std::string::npos);
    CHECK(html.find("copyAttr") != std::string::npos);
    CHECK(html.find("团队综合") != std::string::npos);
    CHECK(html.find("id=\"cat\"") != std::string::npos);
}
