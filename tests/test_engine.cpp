// 引擎与数据契约测试（PLAN §14.1：未知版本拒绝 / 状态机 / 转义 / 哈希向量 / 编码）
#include "test_macros.hpp"

#include <nlohmann/json.hpp>

#include "core/evidence.hpp"
#include "core/model.hpp"
#include "core/report.hpp"
#include "core/session.hpp"
#include "core/sha256.hpp"
#include "core/util.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <thread>

using namespace ctfir;

// ---------------- SHA-256 标准向量 ----------------

CTFIR_TEST(sha256_nist_vectors) {
    CHECK_EQ(Sha256::hex_of("", 0),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(Sha256::hex_of("abc", 3),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    // 填充边界向量：'x'*55..65 —— 已与 Windows certutil（独立实现）交叉验证固化（TEST_RESULTS #15）
    {
        const std::string x55(55, 'x'), x56(56, 'x'), x57(57, 'x'),
            x63(63, 'x'), x64(64, 'x'), x65(65, 'x');
        CHECK_EQ(Sha256::hex_of(x55.data(), x55.size()),
                 std::string("d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072"));
        CHECK_EQ(Sha256::hex_of(x56.data(), x56.size()),
                 std::string("04c26261370ee7541549d16dee320c723e3fd14671e66a099afe0a377c16888e"));
        CHECK_EQ(Sha256::hex_of(x57.data(), x57.size()),
                 std::string("ae14a2563ccf969d99aca69ce6bb74981f734bbf9f655f73b8f06db68cab5217"));
        CHECK_EQ(Sha256::hex_of(x63.data(), x63.size()),
                 std::string("75220b47218278e656f2013bb8f0c455a25eaf01e86c64924e9d48d89776d6f2"));
        CHECK_EQ(Sha256::hex_of(x64.data(), x64.size()),
                 std::string("7ce100971f64e7001e8fe5a51973ecdfe1ced42befe7ee8d5fd6219506b5393c"));
        CHECK_EQ(Sha256::hex_of(x65.data(), x65.size()),
                 std::string("9537c5fdf120482f7d58d25e9ed583f52c02b4e304ea814db1633ad565aed7e9"));
    }
    Sha256 big;
    std::string chunk(1000, 'a');
    for (int i = 0; i < 1000; ++i) big.update(chunk.data(), chunk.size());
    unsigned char d[32];
    big.final(d);
    std::string hex(64, '0');
    static const char* hx = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hex[i * 2] = hx[d[i] >> 4];
        hex[i * 2 + 1] = hx[d[i] & 0xF];
    }
    CHECK_EQ(hex, std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

CTFIR_TEST(sha256_stream_equals_oneshot) {
    std::string data = "ctfir streaming equals one-shot: 账户/计划任务/hosts";
    Sha256 s;
    size_t half = data.size() / 2;
    s.update(data.data(), half);
    s.update(data.data() + half, data.size() - half);
    unsigned char d[32];
    s.final(d);
    std::string hex(64, '0');
    static const char* hx = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hex[i * 2] = hx[d[i] >> 4];
        hex[i * 2 + 1] = hx[d[i] & 0xF];
    }
    CHECK_EQ(hex, Sha256::hex_of(data.data(), data.size()));
}

// ---------------- UTF-8 校验与清洗 ----------------

CTFIR_TEST(sanitize_utf8_replaces_invalid_bytes) {
    std::string bad = "ok";
    bad += char(0xFF);
    bad += "中";
    bad += char(0xC3) + std::string("x");
    std::string out = sanitize_utf8(bad);
    CHECK(is_valid_utf8(out));
    CHECK(out.find("中") != std::string::npos);
    CHECK(out.find("\\xFF") != std::string::npos);
}

// ---------------- 安全文件读取 ----------------

static std::string tmp_path(const char* name) {
    const char* t = std::getenv("TEMP");
#if defined(_WIN32)
    std::string dir = t ? t : "C:\\Windows\\Temp";
    return dir + "\\" + name;
#else
    std::string dir = t ? t : "/tmp";
    return dir + "/" + name;
#endif
}

CTFIR_TEST(read_text_file_utf8_and_missing) {
    std::string p = tmp_path("ctfir_test_utf8.txt");
    { std::ofstream f(p, std::ios::binary); f << "hello 账户\nline2"; }
    ReadResult r = read_text_file(p, 1024 * 1024);
    CHECK(r.ok);
    CHECK_EQ(r.access_status, std::string("ok"));
    CHECK_EQ(r.encoding, std::string("utf8"));
    CHECK(r.content.find("账户") != std::string::npos);
    ReadResult miss = read_text_file(p + ".nonexistent", 1024);
    CHECK(!miss.ok);
    CHECK_EQ(miss.access_status, std::string("not_found"));
    std::remove(p.c_str());
}

CTFIR_TEST(read_text_file_truncation_cap) {
    std::string p = tmp_path("ctfir_test_big.txt");
    { std::ofstream f(p, std::ios::binary); f << std::string(10000, 'x'); }
    ReadResult r = read_text_file(p, 1000);
    CHECK(r.ok);
    CHECK(r.truncated);
    CHECK_EQ(r.access_status, std::string("partial"));
    CHECK_EQ(r.content.size(), static_cast<size_t>(1000));
    std::remove(p.c_str());
}

CTFIR_TEST(read_text_file_non_utf8_marked) {
    std::string p = tmp_path("ctfir_test_gbk.bin");
    { std::ofstream f(p, std::ios::binary); f << "name=" << char(0xD5) << char(0xCB) << char(0xB5) << char(0xC4); }
    ReadResult r = read_text_file(p, 1024);
    CHECK(r.ok);
    CHECK_EQ(r.encoding, std::string("non_utf8_raw"));
    std::remove(p.c_str());
}

// ---------------- 模型：roundtrip 与未知版本拒绝 ----------------

CTFIR_TEST(session_json_roundtrip) {
    ScanSession s;
    s.session_id = "sess-test-1";
    s.started_utc = "2026-11-08T12:00:00Z";
    s.ended_utc = "2026-11-08T12:00:01Z";
    s.overall_status = "COMPLETE";
    ModuleResult m;
    m.module_id = "LNX.ACC";
    m.status = ModuleStatus::PASS;
    m.planned_sources = {"/etc/passwd"};
    m.checked_sources = {"/etc/passwd"};
    s.modules.push_back(m);
    std::string js = session_to_json(s);
    ScanSession back;
    std::string reason;
    CHECK(session_from_json(js, back, reason));
    CHECK_EQ(back.session_id, std::string("sess-test-1"));
    CHECK_EQ(back.modules.size(), static_cast<size_t>(1));
    CHECK_EQ(back.modules[0].module_id, std::string("LNX.ACC"));
    CHECK(back.modules[0].status == ModuleStatus::PASS);
}

CTFIR_TEST(session_json_rejects_unknown_schema) {
    std::string js = R"({"schema_version": 2, "session_id": "x"})";
    ScanSession back;
    std::string reason;
    CHECK(!session_from_json(js, back, reason));
    CHECK(reason.find("schema_version") != std::string::npos);
    std::string bad = R"({"schema_version": "1"})";
    CHECK(!session_from_json(bad, back, reason));
    std::string broken = "{\"schema_version\": 1, ";
    CHECK(!session_from_json(broken, back, reason));
}

// ---------------- 引擎：状态机 / 取消 / 超时 / 建议注册 ----------------

CTFIR_TEST(engine_pass_and_outputs) {
    ScanConfig cfg;
    cfg.out_dir = tmp_path("ctfir_sess_test_out");
    cfg.module_budget_ms = 5000;
    Session sess(cfg);
    sess.set_host_info("TestOS", "1.0", "x64", "user");
    std::string reason;
    CHECK(sess.prepare_out_dir(reason));
    Session::ModuleDef d;
    d.id = "TEST.PASS";
    d.platform = "linux";
    d.fn = [](ModuleCtx& ctx) {
        ctx.planned_source("src1");
        ctx.checked_source("src1");
        Evidence e;
        e.source_kind = "file";
        e.source_path = "/etc/passwd";
        e.payload = "root:x:0:0";
        e.line_context = "passwd:1";
        ctx.add_evidence(e);
        ctx.set_status(ModuleStatus::PASS);
    };
    std::vector<Session::ModuleDef> mods;
    mods.push_back(d);
    sess.run(mods);
    CHECK_EQ(sess.session().overall_status, std::string("COMPLETE"));
    CHECK(sess.session().modules[0].status == ModuleStatus::PASS);
    CHECK_EQ(sess.session().modules[0].evidence_ids.size(), static_cast<size_t>(1));
    CHECK_EQ(sess.evidence().size(), static_cast<size_t>(1));
    CHECK(sess.write_outputs(reason));
    std::ifstream f(cfg.out_dir + "/session.json");
    CHECK(f.good());
    std::ifstream g(cfg.out_dir + "/integrity.sha256");
    CHECK(g.good());
    std::ifstream ev(cfg.out_dir + "/events.jsonl");
    CHECK(ev.good());
}

CTFIR_TEST(engine_finding_advice_and_html_escape) {
    ScanConfig cfg;
    cfg.out_dir = tmp_path("ctfir_sess_test_out2");
    cfg.module_budget_ms = 5000;
    Session sess(cfg);
    sess.set_host_info("TestOS", "1.0", "x64", "user");
    std::string reason;
    CHECK(sess.prepare_out_dir(reason));
    Session::ModuleDef d;
    d.id = "TEST.FIND";
    d.platform = "linux";
    d.fn = [](ModuleCtx& ctx) {
        Evidence e;
        e.source_kind = "file";
        e.source_path = "/etc/passwd";
        e.payload = "backdoor:x:0:0";
        ctx.add_evidence(e);
        Finding f;
        f.rule_id = "LNX.ACC.UID0.001";
        f.severity = "high";
        f.confidence = "medium";
        f.rationale = "非root UID0 <script>alert(1)</script>";
        f.advice_id = "ADVICE.ACC.REVIEW.001";
        ctx.add_finding(f);
        ctx.set_status(ModuleStatus::PASS);
    };
    std::vector<Session::ModuleDef> mods;
    mods.push_back(d);
    sess.run(mods);
    CHECK_EQ(sess.findings().size(), static_cast<size_t>(1));
    CHECK_EQ(sess.session().modules[0].has_findings, true);
    auto advices = advices_for(sess.findings());
    CHECK_EQ(advices.size(), static_cast<size_t>(1));
    CHECK(advices[0].text.find("先解释") != std::string::npos);
    std::string html = build_html_report(sess.session(), sess.evidence(), sess.findings(),
                                         advices, beijing_time_str(now_utc_iso8601()));
    CHECK(html.find("<script>alert(1)</script>") == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
}

CTFIR_TEST(engine_unregistered_advice_cleared) {
    ScanConfig cfg;
    cfg.out_dir = tmp_path("ctfir_sess_test_out2b");
    cfg.module_budget_ms = 5000;
    Session sess(cfg);
    sess.set_host_info("T", "1", "x", "user");
    std::string reason;
    sess.prepare_out_dir(reason);
    Session::ModuleDef d;
    d.id = "TEST.FIND2";
    d.platform = "linux";
    d.fn = [](ModuleCtx& ctx) {
        Finding f;
        f.rule_id = "X.Y.Z.001";
        f.advice_id = "ADVICE.NOT.REGISTERED";
        f.rationale = "r";
        ctx.add_finding(f);
        ctx.set_status(ModuleStatus::PASS);
    };
    std::vector<Session::ModuleDef> mods;
    mods.push_back(d);
    sess.run(mods);
    CHECK_EQ(sess.findings().size(), static_cast<size_t>(1));
    CHECK_EQ(sess.findings()[0].advice_id, std::string(""));
}

CTFIR_TEST(engine_exception_becomes_error_and_restricted) {
    ScanConfig cfg;
    cfg.out_dir = tmp_path("ctfir_sess_test_out3");
    cfg.module_budget_ms = 5000;
    Session sess(cfg);
    sess.set_host_info("T", "1", "x", "user");
    std::string reason;
    sess.prepare_out_dir(reason);
    Session::ModuleDef d;
    d.id = "TEST.THROW";
    d.platform = "linux";
    d.fn = [](ModuleCtx&) { throw std::runtime_error("boom"); };
    std::vector<Session::ModuleDef> mods;
    mods.push_back(d);
    sess.run(mods);
    CHECK_EQ(module_status_str(sess.session().modules[0].status), std::string("ERROR"));
    CHECK_EQ(sess.session().overall_status, std::string("PARTIAL"));
}

CTFIR_TEST(engine_cancel_keeps_partial) {
    ScanConfig cfg;
    cfg.out_dir = tmp_path("ctfir_sess_test_out4");
    cfg.module_budget_ms = 5000;
    Session sess(cfg);
    sess.set_host_info("T", "1", "x", "user");
    std::string reason;
    sess.prepare_out_dir(reason);
    Session::ModuleDef d1;
    d1.id = "TEST.C1";
    d1.platform = "linux";
    d1.fn = [](ModuleCtx& ctx) {
        ctx.request_cancel(); // 模拟用户在模块执行期间取消
        ctx.set_status(ModuleStatus::PASS);
    };
    Session::ModuleDef d2;
    d2.id = "TEST.C2";
    d2.platform = "linux";
    d2.fn = [](ModuleCtx& ctx) { ctx.set_status(ModuleStatus::PASS); };
    std::vector<Session::ModuleDef> mods;
    mods.push_back(d1);
    mods.push_back(d2);
    sess.run(mods);
    CHECK_EQ(sess.session().overall_status, std::string("CANCELLED"));
    CHECK(sess.session().modules[0].status == ModuleStatus::PASS);
    CHECK(sess.session().modules[1].status == ModuleStatus::SKIPPED);
}

CTFIR_TEST(engine_budget_timeout_fallback) {
    ScanConfig cfg;
    cfg.out_dir = tmp_path("ctfir_sess_test_out5");
    cfg.module_budget_ms = 5;
    Session sess(cfg);
    sess.set_host_info("T", "1", "x", "user");
    std::string reason;
    sess.prepare_out_dir(reason);
    Session::ModuleDef d;
    d.id = "TEST.SLOW";
    d.platform = "linux";
    d.fn = [](ModuleCtx&) {
        std::this_thread::sleep_for(std::chrono::milliseconds(60)); // 超预算
        // 未置终态 → 引擎按 expired() 兜底 TIMEOUT
    };
    std::vector<Session::ModuleDef> mods;
    mods.push_back(d);
    sess.run(mods);
    CHECK_EQ(module_status_str(sess.session().modules[0].status), std::string("TIMEOUT"));
    CHECK_EQ(sess.session().overall_status, std::string("PARTIAL"));
}

CTFIR_TEST(report_json_roundtrip_and_disclaimer) {
    ScanConfig cfg;
    cfg.out_dir = tmp_path("ctfir_sess_test_out6");
    cfg.module_budget_ms = 5000;
    Session sess(cfg);
    sess.set_host_info("T", "1", "x", "user");
    std::string reason;
    sess.prepare_out_dir(reason);
    Session::ModuleDef d;
    d.id = "TEST.RJ";
    d.platform = "linux";
    d.fn = [](ModuleCtx& ctx) {
        Finding f;
        f.rule_id = "LNX.ACC.UID0.001";
        f.severity = "high";
        f.confidence = "high";
        f.rationale = "测试";
        f.advice_id = "ADVICE.ACC.REVIEW.001";
        ctx.add_finding(f);
        ctx.set_status(ModuleStatus::PASS);
    };
    std::vector<Session::ModuleDef> mods;
    mods.push_back(d);
    sess.run(mods);
    auto advices = advices_for(sess.findings());
    std::string jr = build_json_report(sess.session(), sess.evidence(), sess.findings(), advices);
    // 可解析 & 含免责声明
    {
        auto j = nlohmann::json::parse(jr); // 不可解析会抛出 → 用例失败
        CHECK(j.contains("disclaimer"));
        CHECK(j.contains("findings"));
    }
    CHECK(jr.find("只读扫描结果") != std::string::npos);
    CHECK(jr.find("never_auto_execute") != std::string::npos);
}
