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
    auto d=display_action(mk("WIN.ACC.DOLLAR.001","NetUserEnum:ctfir-marker$"));
    CHECK(d.command.find("net user")!=std::string::npos);
    CHECK(d.command.find("ctfir-marker$")!=std::string::npos);
    auto a=display_action(mk("LNX.ACC.UID0.001","/etc/passwd:aihelp"));
    CHECK(a.command.find("getent passwd")!=std::string::npos);
    CHECK(a.command.find("aihelp")!=std::string::npos);
    CHECK(a.command.find("usermod")==std::string::npos);
    auto timer=display_action(mk("LNX.TIMER.FACT.001","/etc/systemd/system/legal.timer"));
    CHECK(timer.command.find("systemctl cat")!=std::string::npos);
    CHECK(timer.command.find("disable")==std::string::npos);
    CHECK(timer.command.find("stop")==std::string::npos);
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
    CHECK(html.find("1.复核") != std::string::npos);
    CHECK(html.find("怎么处理") != std::string::npos);
    CHECK(html.find("决赛") == std::string::npos);
    CHECK(html.find("只读") != std::string::npos);
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

CTFIR_TEST(linux_unverified_privilege_facts_are_not_cleanup_orders) {
    Finding f; f.rule_id = "LNX.SUID.UNEXPECTED.001"; f.object_ref = "/usr/bin/ctfir-marker-package-tool"; f.confidence = "low";
    CHECK(bucket_of(f) == Bucket::Trace);
    CHECK(!plan_remediation(f).supported);
    CHECK(display_action(f).command.find("chmod") == std::string::npos);
    f.confidence = "high"; CHECK(bucket_of(f) == Bucket::Clear);
    f.rule_id = "LNX.CAPS.UNEXPECTED.001"; CHECK(bucket_of(f) == Bucket::Trace);
}

#include "core/fixengine.hpp"
#include "core/safety_rule_catalog.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iostream>

CTFIR_TEST(all_referenced_rules_have_no_mutation_plan_or_generated_actions) {
    for (const char* rid:kSafetyRuleCatalog) {
        auto f=mk(rid,"/etc/ctfir-marker.conf:1");
        auto p=plan_remediation(f);
        CHECK(!p.supported); CHECK(p.steps.empty()); CHECK(p.backups.empty()); CHECK(p.native_ops.empty());
        auto text=display_action(f).command+instantiate_advice(f);
        for(const char* dangerous:{"userdel", "usermod", "pkill", "killall", "kill -", "passwd -l", "sed -i", "rm -", "disable --now", "systemctl stop", "crontab -r", "taskkill", "sc delete", "reg delete"})
            CHECK(text.find(dangerous)==std::string::npos);
        FixContext fx; fx.assume_yes=true;
        CHECK(!run_remediation(f,p,fx)); CHECK(fx.executed==0);
    }
}
CTFIR_TEST(forged_legacy_unknown_and_mixed_plans_never_execute_even_yes) {
    namespace fs=std::filesystem;
    auto folder=fs::temp_directory_path()/("ctfir-marker-safety-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(folder);
    auto canary=folder/"canary.txt";{std::ofstream out(canary);out<<"KEEP";}
    auto input_backup=std::cin.rdbuf();
    for(const char* input:{"", "\n", "n\n", "no\n", "yes\n", "y\n", "Y\n"}) {
        std::istringstream stream(input);std::cin.rdbuf(stream.rdbuf());std::cin.clear();
        for(bool yes:{false,true}) for(bool dry:{false,true}) {
            RemediationPlan p; p.supported=true;
            p.steps={"__LNX_DISABLE_UID0__","__LNX_DELETE_UID0__","UNKNOWN_ACTION","echo CHANGED > \""+canary.string()+"\""};
            p.backups={"echo CHANGED > \""+canary.string()+"\""};
            p.native_ops={"unknown:action","quarantine:"+canary.string(),"linux_comment_line:"+canary.string()+":1"};
            FixContext fx;fx.assume_yes=yes;fx.dry_run=dry;fx.session_dir=folder.string();fx.backup_dir=(folder/"backup").string();
            CHECK(!run_remediation(mk("LNX.ACC.UID0.001","/etc/passwd:aihelp"),p,fx));
            CHECK(fx.executed==0);CHECK(!fs::exists(folder/"backup"));CHECK(!fs::exists(folder/"fix-journal.jsonl"));
            std::ifstream in(canary);std::string content;in>>content;CHECK(content=="KEEP");
        }
    }
    std::cin.rdbuf(input_backup);std::cin.clear();fs::remove(canary);fs::remove(folder);
}
CTFIR_TEST(protected_root_duplicate_uid_and_legitimate_timer_are_preview_only) {
    for(const char* rid:{"LNX.ACC.UID0.001","LNX.ACC.DUPUID.001","LNX.BASE.WEAKPWD.001","LNX.TIMER.FACT.001","LNX.PERSIST.CRON.001","LNX.PERSIST.SYSTEMD.001","UNKNOWN.ACTION.999"}) {
        auto f=mk(rid,"/etc/passwd:root"); CHECK(!plan_remediation(f).supported);
        CHECK(display_action(f).command.find("passwd -")==std::string::npos);
    }
    auto f=mk("LNX.ACC.UID0.001","/etc/passwd:aihelp");CHECK(display_action(f).contest_note.find("NSS")!=std::string::npos);
}

CTFIR_TEST(all_playbook_bodies_are_non_mutating_and_root_protected) {
    for(const char* id:{"ADVICE.ACC.REVIEW.001","ADVICE.LOGIN_HIDE.REVIEW.001","ADVICE.TASK.REVIEW.001","ADVICE.SVC.REVIEW.001","ADVICE.AUTORUN.REVIEW.001","ADVICE.HOSTS.REVIEW.001","ADVICE.SSHKEY.REVIEW.001","ADVICE.CRON.REVIEW.001","ADVICE.PROFILE.REVIEW.001","ADVICE.PRELOAD.REVIEW.001","ADVICE.WEBSHELL.REVIEW.001","ADVICE.MINER.REVIEW.001","ADVICE.HASH.BASELINE.001","ADVICE.FILE.REVIEW.001","ADVICE.HARDEN.001","ADVICE.AD.REVIEW.001","ADVICE.EVENTLOG.REVIEW.001","ADVICE.TOOLS.REVIEW.001","ADVICE.RANSOM.REVIEW.001","ADVICE.RMT.REVIEW.001","ADVICE.MID.REVIEW.001"}) {
        auto a=find_advice(id); CHECK(a!=nullptr); if(!a)continue;
        std::string text=a->text;
        for(const char* bad:{"userdel","usermod","pkill","killall","passwd -l","systemctl stop","crontab -r","sed -i"}) CHECK(text.find(bad)==std::string::npos);
    }
}
