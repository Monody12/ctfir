#include "test_macros.hpp"
#include "core/triage.hpp"
#include "core/display_action.hpp"
#include "core/remediate.hpp"
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
    CHECK_EQ(bucket_of("WIN.FILES.TEMPEXE.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("X.UNKNOWN.001"), Bucket::Trace);
    CHECK_EQ(bucket_of("WIN.AD.GPP.CPASSWORD.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AD.NTDS.COPY.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AD.GPO.TASK.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AD.DSRM.LOGON.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.AD.SPOOLER.DC.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.AD.ROLE.001"), Bucket::Inventory);
    CHECK_EQ(bucket_of("WIN.BASE.WDIGEST.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.BASE.LASTUSER.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.AD.GPP.ADMIN.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AD.GPP.REG.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AD.GPP.FILE.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AD.HIVE.COPY.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AD.LSASS.DMP.001"), Bucket::Clear);
    CHECK_EQ(bucket_of("WIN.AD.MACHPWD.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.BASE.UAC.NOPROMPT.001"), Bucket::Harden);
    CHECK_EQ(bucket_of("WIN.BASE.REMOTEREG.001"), Bucket::Harden);
}

CTFIR_TEST(triage_titles_and_visibility) {
    Finding dollar = mk("WIN.ACC.DOLLAR.001", "NetUserEnum:ctfir-marker$");
    Triage t = triage_of(dollar);
    CHECK(t.title_zh.find("美元") != std::string::npos);
    CHECK(t.default_visible);

    Finding inv = mk("WIN.ACC.INVENTORY.001", "NetUserEnum", "info");
    CHECK(triage_of(inv).default_visible);
    CHECK(finding_visible(inv, ViewPreset::Personal, "all", "all", ""));
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

CTFIR_TEST(triage_exam_order_web_before_harden) {
    std::vector<Finding> fds;
    fds.push_back(mk("WIN.BASE.UAC.001", "EnableLUA", "high"));
    fds.push_back(mk("LNX.WEB.SHELL.001", "/var/www/html/a.php", "high"));
    fds.push_back(mk("WIN.WEB.LOGPOST.001", "W3SVC", "medium"));
    auto idx = sorted_finding_indices(fds);
    CHECK_EQ(fds[idx[0]].rule_id, std::string("LNX.WEB.SHELL.001"));
    CHECK_EQ(fds[idx[1]].rule_id, std::string("WIN.WEB.LOGPOST.001"));
    CHECK_EQ(fds[idx[2]].rule_id, std::string("WIN.BASE.UAC.001"));
    CHECK_EQ(bucket_rank(Bucket::Clear), 0);
    CHECK_EQ(bucket_rank(Bucket::Web), 1);
    CHECK_EQ(bucket_rank(Bucket::Trace), 2);
    CHECK_EQ(bucket_rank(Bucket::Harden), 3);
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

    auto gpp = display_action(mk("WIN.AD.GPP.CPASSWORD.001",
                                 "C:\\Windows\\SYSVOL\\sysvol\\ctfir.local\\Policies\\x\\Groups.xml"));
    CHECK(gpp.command.find("del /f") != std::string::npos);
    CHECK(gpp.command.find("Groups.xml") != std::string::npos);

    auto wdigest = display_action(mk("WIN.BASE.WDIGEST.001", "WDigest\\UseLogonCredential"));
    CHECK(wdigest.command.find("UseLogonCredential") != std::string::npos);
    CHECK(wdigest.command.find("/d 0") != std::string::npos);

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

    Finding uid0 = mk("LNX.ACC.UID0.001", "/etc/passwd:ctfir-marker", "high");
    auto u0 = display_action(uid0);
    CHECK(u0.command.find("ctfir-marker") != std::string::npos);
    CHECK(u0.command.find("usermod") != std::string::npos);
    CHECK(u0.command.find("27") == std::string::npos);

    Finding sudoers = mk("LNX.ACC.SUDOERS.001", "/etc/sudoers.d/ctfir-marker:1", "medium");
    auto su = display_action(sudoers);
    CHECK(su.command.find("rm -f") != std::string::npos);
    CHECK(su.command.find("/etc/sudoers.d/ctfir-marker") != std::string::npos);

    Finding sshc = mk("LNX.SSH.CONFIG.001", "/etc/ssh/sshd_config:146", "low");
    auto sc = display_action(sshc);
    CHECK(sc.command.find("PermitRootLogin") != std::string::npos);
    CHECK(sc.command.find("sed") != std::string::npos);

    auto inv = display_action(mk("WIN.ACC.INVENTORY.001", "NetUserEnum", "info"));
    CHECK(inv.command.find("无需删除") != std::string::npos);

    auto appinit = display_action(mk("WIN.AUTORUN.APPINIT.001", "Windows\\AppInit_DLLs"));
    CHECK(appinit.command.find("AppInit_DLLs") != std::string::npos);
    CHECK(appinit.command.find("打开") == std::string::npos);

    auto run = display_action(mk("WIN.AUTORUN.SUSPECT.001", "HKLM\\...\\Run(64)\\ctfir-marker"));
    CHECK(run.command.find("reg delete") != std::string::npos);
    CHECK(run.command.find("ctfir-marker") != std::string::npos);

    auto svc = display_action(mk("WIN.SVC.SUSPECT.001", "Services\\ctfir-marker-WinUpdate"));
    CHECK(svc.command.find("sc delete") != std::string::npos);
    CHECK(svc.command.find("ctfir-marker-WinUpdate") != std::string::npos);

    auto task = display_action(mk("WIN.TASK.SUSPECT.001", "Task\\ctfir-marker-sync"));
    CHECK(task.command.find("schtasks") != std::string::npos);
    CHECK(task.command.find("ctfir-marker-sync") != std::string::npos);

    auto psh = display_action(mk("WIN.TRACE.PSHIST.001",
        "C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt:1"));
    CHECK(psh.command.find("打开") == std::string::npos);
    CHECK(psh.command.find("ConsoleHost_history") != std::string::npos);

    Finding hosts_l = mk("LNX.HOSTS.MAP.001", "/etc/hosts:8", "low", "r", "ADVICE.HOSTS.REVIEW.001");
    auto hl = display_action(hosts_l);
    CHECK(hl.command.find("sed") != std::string::npos);
    CHECK(hl.command.find("flushdns") == std::string::npos);
    std::string ha = instantiate_advice_body(hosts_l);
    CHECK(ha.find("flushdns") == std::string::npos);
    CHECK(ha.find("127.0.1.1") != std::string::npos);

    Finding hosts_w = mk("WIN.HOSTS.MAP.001",
                         "C:\\Windows\\System32\\drivers\\etc\\hosts:25", "low", "r",
                         "ADVICE.HOSTS.REVIEW.001");
    auto hw = display_action(hosts_w);
    CHECK(hw.command.find("flushdns") != std::string::npos);
    std::string hwa = instantiate_advice_body(hosts_w);
    CHECK(hwa.find("flushdns") != std::string::npos);
    CHECK(hwa.find("127.0.1.1") == std::string::npos);

    Finding tools = mk("WIN.TOOLS.ARTIFACT.001", "C:\\Users\\Administrator\\Desktop\\fscan.exe",
                       "medium", "r", "ADVICE.TOOLS.REVIEW.001");
    std::string ta = instantiate_advice_body(tools);
    CHECK(ta.find("挖矿") == std::string::npos);
    CHECK(ta.find("fscan") != std::string::npos || ta.find("工具") != std::string::npos);

    Finding inv_acc = mk("WIN.ACC.INVENTORY.001", "NetUserEnum", "info", "r", "ADVICE.ACC.REVIEW.001");
    std::string ia = instantiate_advice_body(inv_acc);
    CHECK(ia.find("NetUserEnum 看组") == std::string::npos);
    CHECK(ia.find("<账户名>") == std::string::npos);
    CHECK(ia.find("<用户名>") == std::string::npos);

    Finding hashw = mk("WIN.FILES.BASELINE.001", "C:\\Windows\\System32\\netstat.exe",
                       "medium", "r", "ADVICE.HASH.BASELINE.001");
    std::string hb = instantiate_advice_body(hashw);
    CHECK(hb.find("rpm") == std::string::npos);
    CHECK(hb.find("del") != std::string::npos || hb.find("copy") != std::string::npos);

    Finding hashl = mk("LNX.BASE.CMDSIZE.001", "/usr/bin/ls", "medium", "r",
                       "ADVICE.HASH.BASELINE.001");
    std::string hbl = instantiate_advice_body(hashl);
    CHECK(hbl.find("rpm") != std::string::npos);

    auto te = display_action(mk("WIN.FILES.TEMPEXE.001", "C:\\Users\\Public\\evil.svc.exe"));
    CHECK(te.command.find("del") != std::string::npos);
    CHECK(te.command.find("无需删除") == std::string::npos);

    Finding evc = mk("WIN.EVT.ACC.CREATE.001", "Security 4720:ctfir-marker$", "medium", "r",
                     "ADVICE.EVENTLOG.REVIEW.001");
    std::string eva = instantiate_advice_body(evc);
    CHECK(eva.find("<账户名>") == std::string::npos);
    CHECK(eva.find("可疑账户") == std::string::npos);

    auto gid = display_action(mk("LNX.ACC.GID0.001", "/etc/group:ctfir-marker-g"));
    CHECK(gid.command.find("ctfir-marker-g") != std::string::npos);
    CHECK(gid.command.find("用户名") == std::string::npos);

    Finding sshlog = mk("LNX.PERSIST.SSHLOG.001", "/tmp/.sshlog", "high", "r",
                        "ADVICE.TOOLS.REVIEW.001");
    std::string sla = instantiate_advice_body(sshlog);
    CHECK(sla.find("可疑账户") == std::string::npos);
    CHECK(sla.find("sshlog") != std::string::npos || sla.find("删") != std::string::npos);

    auto pwdmax = display_action(mk("LNX.BASE.PWDMAX.001", "/etc/login.defs"));
    CHECK(pwdmax.command.find("PASS_MAX_DAYS") != std::string::npos);
    CHECK(pwdmax.command.find("打开") == std::string::npos);

    auto blink = display_action(mk("LNX.WEB.BLACKLINK.001", "/var/www/html/index.php"));
    CHECK(blink.command.find("index.php") != std::string::npos);
    CHECK(blink.command.find("quarantine") == std::string::npos);
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
    CHECK(triage_of(ms).default_visible);
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
    CHECK(html.find("团队综合") == std::string::npos);
    CHECK(html.find("个人防护") == std::string::npos);
    CHECK(html.find("id=\"cat\"") != std::string::npos);
    CHECK(html.find("1.先清") != std::string::npos);
    CHECK(html.find("怎么处理") != std::string::npos);
    CHECK(html.find("决赛") == std::string::npos);
    CHECK(html.find("只读") == std::string::npos);
}

CTFIR_TEST(display_action_untrusted_object_no_shell_injection) {
    Finding f;
    f.rule_id = "LNX.PERSIST.INITD.001";
    f.object_ref = "/etc/init.d/$(touch /tmp/unwanted):1";
    CHECK(display_action(f).command.empty());
    CHECK(!plan_remediation(f).supported);
    f.rule_id = "LNX.PERSIST.XINETD.001";
    CHECK(!plan_remediation(f).supported);
    f.rule_id = "WIN.SVC.SUSPECT.001";
    f.object_ref = "evil\" & calc & \"";
    CHECK(display_action(f).command.empty());
}

CTFIR_TEST(linux_process_snapshot_never_generates_kill) {
    for (const auto& rid : {"LNX.PROC.NAMEMISMATCH.001", "LNX.PROC.MINER.001", "LNX.PROC.TMPDIR.001", "LNX.PROC.SUSPECT.001"}) {
        for (const auto& pid : {"1", "913", "2703"}) {
            Finding f; f.rule_id = rid; f.object_ref = std::string("PID ") + pid;
            CHECK(!plan_remediation(f).supported);
            auto action = display_action(f);
            CHECK(action.command.find("kill ") == std::string::npos);
            CHECK(action.command.find("ps -p ") != std::string::npos);
        }
    }
}
