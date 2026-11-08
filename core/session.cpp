#include "session.hpp"
#include "advice.hpp"
#include "report.hpp"
#include "util.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace ctfir {

// ---------------- ModuleCtx ----------------

ModuleCtx::ModuleCtx(Session& s, ModuleResult& mr, std::atomic<bool>& cancel,
                     std::chrono::steady_clock::time_point deadline, long long budget_ms)
    : s_(s), mr_(mr), cancel_(cancel), deadline_(deadline), budget_ms_(budget_ms),
      evidence_base_(s.evidence_.size()), finding_base_(s.findings_.size()) {}

bool ModuleCtx::cancelled() const { return cancel_; }

bool ModuleCtx::expired() const {
    return std::chrono::steady_clock::now() >= deadline_;
}

long long ModuleCtx::remaining_ms() const {
    auto d = std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - std::chrono::steady_clock::now()).count();
    return d < 0 ? 0 : d;
}

void ModuleCtx::set_status(ModuleStatus st) { mr_.status = st; }

void ModuleCtx::note(const std::string& txt) {
    if (!mr_.status_note.empty()) mr_.status_note += "; ";
    mr_.status_note += sanitize_utf8(txt);
}

void ModuleCtx::error(const std::string& code_and_msg) {
    mr_.errors.push_back(sanitize_utf8(code_and_msg));
}

void ModuleCtx::planned_source(const std::string& src) {
    mr_.planned_sources.push_back(sanitize_utf8(src));
}

void ModuleCtx::checked_source(const std::string& src) {
    mr_.checked_sources.push_back(sanitize_utf8(src));
}

void ModuleCtx::omitted_source(const std::string& src, const std::string& reason) {
    mr_.omitted_sources.push_back(sanitize_utf8(src) + " (" + sanitize_utf8(reason) + ")");
}

void ModuleCtx::add_evidence(Evidence e) {
    e.evidence_id = random_id("ev");
    e.collector = sanitize_utf8(mr_.module_id);
    e.collector_version = mr_.module_version;
    e.capture_time_utc = now_utc_iso8601();
    if (e.trust.empty()) e.trust = "live_local";
    if (e.redaction.empty()) e.redaction = "none";
    e.source_path = sanitize_utf8(e.source_path);
    e.payload = sanitize_utf8(e.payload);
    e.line_context = sanitize_utf8(e.line_context);
    for (auto& l : e.limitations) l = sanitize_utf8(l);
    s_.evidence_.push_back(std::move(e));
    mr_.evidence_ids.push_back(s_.evidence_.back().evidence_id);
}

void ModuleCtx::add_finding(Finding f) {
    f.finding_id = random_id("fd");
    f.platform = sanitize_utf8(s_.s_.platform_);
    f.status = "FINDING";
    f.rule_version = f.rule_version.empty() ? "1.0.0" : f.rule_version;
    f.rationale = sanitize_utf8(f.rationale);
    for (auto& l : f.limitations) l = sanitize_utf8(l);
    if (!find_advice(f.advice_id))
        f.advice_id = ""; // 未注册的建议 ID 不外泄（防伪造）
    s_.findings_.push_back(std::move(f));
    mr_.has_findings = true;
    mr_.finding_ids.push_back(s_.findings_.back().finding_id);
}

std::string ModuleCtx::save_raw(const std::string& content, const std::string& suggested_name,
                                std::string& sha_out) {
    sha_out.clear();
    if (!s_.cfg_.save_raw_evidence) return "";
    try {
        fs::path ev_dir = fs::path(s_.cfg_.out_dir) / "evidence";
        fs::create_directories(ev_dir);
        std::string safe_name;
        for (char c : suggested_name)
            safe_name += (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')
                             ? c : '_';
        std::string eid = random_id("raw");
        fs::path file = ev_dir / (eid + "_" + safe_name);
        std::ofstream of(file, std::ios::binary);
        if (!of) return "";
        of.write(content.data(), static_cast<std::streamsize>(content.size()));
        of.close();
        sha_out = Sha256::hex_of(content.data(), content.size());
        return "evidence/" + file.filename().string();
    } catch (...) {
        return "";
    }
}

void ModuleCtx::request_cancel() { cancel_ = true; }

const ScanConfig& ModuleCtx::config() const { return s_.cfg_; }

// ---------------- Session ----------------

Session::Session(ScanConfig cfg) : cfg_(std::move(cfg)) {}

void Session::set_host_info(const std::string& os_name, const std::string& os_version,
                            const std::string& os_arch, const std::string& privilege) {
    s_.os_name = sanitize_utf8(os_name);
    s_.os_version = sanitize_utf8(os_version);
    s_.os_arch = sanitize_utf8(os_arch);
    s_.privilege = sanitize_utf8(privilege);
}

bool Session::prepare_out_dir(std::string& reason) {
    std::error_code ec;
    fs::create_directories(fs::u8path(cfg_.out_dir), ec);
    // 可写探针：写临时文件
    fs::path probe = fs::path(cfg_.out_dir) / ".ctfir-write-probe";
    {
        std::ofstream of(probe, std::ios::binary);
        if (!of) { reason = "out_dir not writable: " + cfg_.out_dir; return false; }
        of << "ok";
    }
    fs::remove(probe, ec);
    s_.session_id = random_id("sess");
    s_.started_utc = now_utc_iso8601();
    return true;
}

void Session::event(const std::string& name, const std::string& module_id, const std::string& detail) {
    if (event_hook) {
        std::string d = detail;
        try { event_hook(name, module_id, d); } catch (...) { /* UI 回调异常不阻断扫描 */ }
    }
    if (!events_stream_) return;
    std::ofstream& os = *static_cast<std::ofstream*>(events_stream_);
    os << "{\"ts_utc\":\"" << now_utc_iso8601() << "\",\"event\":\"" << name
       << "\",\"module\":\"" << sanitize_utf8(module_id) << "\",\"detail\":\""
       << sanitize_utf8(detail) << "\"}\n";
    os.flush();
}

void Session::run(const std::vector<ModuleDef>& mods) {
    namespace ch = std::chrono;
    fs::path ev_file = fs::path(cfg_.out_dir) / "events.jsonl";
    std::ofstream events(ev_file, std::ios::binary);
    events_stream_ = &events;

    for (const auto& def : mods) {
        if (cancel_) {
            ModuleResult mr;
            mr.module_id = def.id;
            mr.module_version = def.version;
            mr.status = ModuleStatus::SKIPPED;
            mr.status_note = "cancelled by user before start";
            s_.modules.push_back(mr);
            event("module_skipped", def.id, "cancelled");
            continue;
        }
        ModuleResult mr;
        mr.module_id = def.id;
        mr.module_version = def.version;
        s_.platform_ = def.platform;
        event("module_start", def.id, "");
        auto t0 = ch::steady_clock::now();
        auto deadline = t0 + ch::milliseconds(cfg_.module_budget_ms);
        ModuleCtx ctx(*this, mr, cancel_, deadline, cfg_.module_budget_ms);
        try {
            def.fn(ctx); // 模块经 ctx 填 status/来源/证据/发现；异常一律 ERROR
        } catch (const std::exception& e) {
            mr.status = ModuleStatus::ERROR;
            mr.errors.push_back(std::string("exception: ") + e.what());
        } catch (...) {
            mr.status = ModuleStatus::ERROR;
            mr.errors.push_back("unknown exception");
        }
        auto elapsed = ch::duration_cast<ch::duration<double, std::milli>>(ch::steady_clock::now() - t0).count();
        mr.elapsed_ms = elapsed;
        if (!module_status_terminal(mr.status)) {
            // 模块忘了给终态：按取消/超时判定兜底，不输出 PENDING
            if (cancel_) { mr.status = ModuleStatus::SKIPPED; mr.status_note += "; cancelled"; }
            else if (ctx.expired()) { mr.status = ModuleStatus::TIMEOUT; mr.status_note += "; budget exhausted"; }
            else { mr.status = ModuleStatus::ERROR; mr.errors.push_back("module returned non-terminal status"); }
        }
        // 权限失败不 PASS（PLAN 硬门禁 T07/T19）：PASS 但存在被拒来源 → 升级为 PERMISSION_DENIED
        if (mr.status == ModuleStatus::PASS) {
            for (const auto& o : mr.omitted_sources) {
                if (o.find("(PERMISSION_DENIED)") != std::string::npos) {
                    mr.status = ModuleStatus::PERMISSION_DENIED;
                    mr.status_note += "; 存在被拒来源，状态按权限受限计（发现仍保留）";
                    break;
                }
            }
        }
        if (mr.status == ModuleStatus::PASS && mr.has_findings) {
            mr.status_note += "; findings attached (module completed)";
        }
        s_.modules.push_back(mr);
        event("module_end", def.id, module_status_str(mr.status));
    }

    s_.ended_utc = now_utc_iso8601();
    // 会话总状态（PLAN §9.2：受限不得报 COMPLETE）
    bool any_fail = false, any_restricted = false, any_findings = false;
    for (const auto& m : s_.modules) {
        if (m.status == ModuleStatus::ERROR || m.status == ModuleStatus::TIMEOUT) any_fail = true;
        if (m.status == ModuleStatus::PERMISSION_DENIED || m.status == ModuleStatus::SKIPPED) any_restricted = true;
        if (m.status == ModuleStatus::UNSUPPORTED && m.unsupported_reason == "capability_missing") any_restricted = true;
        if (m.has_findings) any_findings = true;
    }
    if (cancel_) s_.overall_status = "CANCELLED";
    else if (any_fail) s_.overall_status = "PARTIAL";   // 模块级失败：会话不 COMPLETE（FAILED 留给会话级致命）
    else if (any_restricted) s_.overall_status = "PARTIAL";
    else s_.overall_status = "COMPLETE";
    (void)any_findings;

    events_stream_ = nullptr;
}

bool Session::write_outputs(std::string& err) {
    try {
        fs::path base = fs::u8path(cfg_.out_dir);
        auto atomic_write = [&](const fs::path& file, const std::string& content) {
            fs::path tmp = file;
            tmp += ".tmp";
            {
                std::ofstream of(tmp, std::ios::binary);
                if (!of) throw std::runtime_error("cannot write " + tmp.string());
                of.write(content.data(), static_cast<std::streamsize>(content.size()));
            }
            std::error_code ec;
            fs::remove(file, ec);
            fs::rename(tmp, file, ec);
            if (ec) throw std::runtime_error("rename failed for " + file.string());
        };

        std::vector<std::pair<std::string, std::string>> files; // name, content
        files.emplace_back("session.json", session_to_json(s_));
        {
            std::ostringstream os;
            os << "[\n";
            for (size_t i = 0; i < s_.modules.size(); ++i) {
                os << module_result_to_json(s_.modules[i]);
                if (i + 1 < s_.modules.size()) os << ",";
                os << "\n";
            }
            os << "]\n";
            files.emplace_back("module-results.json", os.str());
        }
        {
            std::ostringstream os;
            os << "[\n";
            for (size_t i = 0; i < findings_.size(); ++i) {
                os << finding_to_json(findings_[i]);
                if (i + 1 < findings_.size()) os << ",";
                os << "\n";
            }
            os << "]\n";
            files.emplace_back("findings.json", os.str());
        }
        {
            std::ostringstream os;
            os << "[\n";
            for (size_t i = 0; i < findings_.size(); ++i) {
                const Advice* a = find_advice(findings_[i].advice_id);
                std::string text = a ? a->text : "(advice missing)";
                // 以 JSON 转义输出
                nlohmann::json j;
                j["finding_id"] = findings_[i].finding_id;
                j["advice_id"] = findings_[i].advice_id;
                j["never_auto_execute"] = true;
                j["text"] = text;
                os << j.dump() << (i + 1 < findings_.size() ? "," : "") << "\n";
            }
            os << "]\n";
            files.emplace_back("advice.json", os.str());
        }
        // 自包含 HTML 报告
        {
            auto advices = advices_for(findings_);
            files.emplace_back("report.html",
                               build_html_report(s_, evidence_, findings_, advices,
                                                 beijing_time_str(now_utc_iso8601())));
        }

        std::string integrity;
        for (auto& f : files) {
            atomic_write(base / f.first, f.second);
            integrity += Sha256::hex_of(f.second.data(), f.second.size()) + "  " + f.first + "\n";
        }
        atomic_write(base / "integrity.sha256", integrity);
        return true;
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
}

} // namespace ctfir
