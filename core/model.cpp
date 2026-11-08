#include "model.hpp"
#include <nlohmann/json.hpp>
#include "util.hpp"

namespace ctfir {

using nlohmann::json;

static json jarr(const std::vector<std::string>& v) {
    return json(v);
}

const char* module_status_str(ModuleStatus s) {
    switch (s) {
    case ModuleStatus::PASS: return "PASS";
    case ModuleStatus::PERMISSION_DENIED: return "PERMISSION_DENIED";
    case ModuleStatus::UNSUPPORTED: return "UNSUPPORTED";
    case ModuleStatus::TIMEOUT: return "TIMEOUT";
    case ModuleStatus::ERROR: return "ERROR";
    case ModuleStatus::SKIPPED: return "SKIPPED";
    case ModuleStatus::PENDING: return "PENDING";
    case ModuleStatus::RUNNING: return "RUNNING";
    }
    return "ERROR";
}

bool module_status_terminal(ModuleStatus s) {
    return s != ModuleStatus::PENDING && s != ModuleStatus::RUNNING;
}

std::string evidence_to_json(const Evidence& e) {
    json j;
    j["evidence_id"] = e.evidence_id;
    j["collector"] = e.collector;
    j["collector_version"] = e.collector_version;
    j["source_kind"] = e.source_kind;
    j["source_path"] = e.source_path;
    j["capture_time_utc"] = e.capture_time_utc;
    j["raw_ref"] = e.raw_ref;
    j["sha256"] = e.sha256;
    j["object_identity"] = e.object_identity;
    j["access_status"] = e.access_status;
    j["trust"] = e.trust;
    j["redaction"] = e.redaction;
    j["limitations"] = jarr(e.limitations);
    j["payload"] = e.payload;
    j["line_context"] = e.line_context;
    return j.dump();
}

std::string finding_to_json(const Finding& f) {
    json j;
    j["schema_version"] = kSchemaVersion;
    j["finding_id"] = f.finding_id;
    j["rule_id"] = f.rule_id;
    j["rule_version"] = f.rule_version;
    j["platform"] = f.platform;
    j["evidence_ids"] = jarr(f.evidence_ids);
    j["evidence_paths"] = jarr(f.evidence_paths);
    j["object_ref"] = f.object_ref;
    j["rationale"] = f.rationale;
    j["severity"] = f.severity;
    j["confidence"] = f.confidence;
    j["evidence_trust"] = f.evidence_trust;
    j["status"] = f.status;
    j["limitations"] = jarr(f.limitations);
    j["advice_id"] = f.advice_id;
    return j.dump();
}

std::string module_result_to_json(const ModuleResult& m) {
    json j;
    j["module_id"] = m.module_id;
    j["module_version"] = m.module_version;
    j["applicable"] = m.applicable;
    j["unsupported_reason"] = m.unsupported_reason;
    j["planned_sources"] = jarr(m.planned_sources);
    j["checked_sources"] = jarr(m.checked_sources);
    j["omitted_sources"] = jarr(m.omitted_sources);
    j["status"] = module_status_str(m.status);
    j["errors"] = jarr(m.errors);
    j["elapsed_ms"] = m.elapsed_ms;
    j["has_findings"] = m.has_findings;
    j["evidence_ids"] = jarr(m.evidence_ids);
    j["finding_ids"] = jarr(m.finding_ids);
    j["status_note"] = m.status_note;
    return j.dump();
}

std::string session_to_json(const ScanSession& s) {
    json j;
    j["schema_version"] = s.schema_version;
    j["session_id"] = s.session_id;
    j["tool_version"] = s.tool_version;
    j["rule_pack_version"] = s.rule_pack_version;
    j["os_name"] = s.os_name;
    j["os_version"] = s.os_version;
    j["os_arch"] = s.os_arch;
    j["privilege"] = s.privilege;
    j["profile"] = s.profile;
    j["started_utc"] = s.started_utc;
    j["ended_utc"] = s.ended_utc;
    j["overall_status"] = s.overall_status;
    j["modules"] = json::array();
    for (const auto& m : s.modules) {
        json jm;
        jm["module_id"] = m.module_id;
        jm["module_version"] = m.module_version;
        jm["applicable"] = m.applicable;
        jm["unsupported_reason"] = m.unsupported_reason;
        jm["planned_sources"] = jarr(m.planned_sources);
        jm["checked_sources"] = jarr(m.checked_sources);
        jm["omitted_sources"] = jarr(m.omitted_sources);
        jm["status"] = module_status_str(m.status);
        jm["errors"] = jarr(m.errors);
        jm["elapsed_ms"] = m.elapsed_ms;
        jm["has_findings"] = m.has_findings;
        jm["evidence_ids"] = jarr(m.evidence_ids);
        jm["finding_ids"] = jarr(m.finding_ids);
        jm["status_note"] = m.status_note;
        j["modules"].push_back(jm);
    }
    return j.dump(2);
}

bool session_from_json(const std::string& text, ScanSession& out, std::string& reason) {
    json j;
    try {
        j = json::parse(text);
    } catch (const std::exception& e) {
        reason = std::string("json parse failed: ") + e.what();
        return false;
    }
    if (!j.contains("schema_version") || !j["schema_version"].is_number_integer()) {
        reason = "missing schema_version";
        return false;
    }
    const int v = j["schema_version"].get<int>();
    if (v != kSchemaVersion) {
        // v1：只接受精确版本；未来 minor 迁移另立流程（PLAN §9.3）
        reason = "schema_version " + std::to_string(v) + " not supported (supported: 1)";
        return false;
    }
    out.schema_version = v;
    out.session_id = j.value("session_id", "");
    out.tool_version = j.value("tool_version", "");
    out.rule_pack_version = j.value("rule_pack_version", "");
    out.os_name = j.value("os_name", "");
    out.os_version = j.value("os_version", "");
    out.os_arch = j.value("os_arch", "");
    out.privilege = j.value("privilege", "");
    out.profile = j.value("profile", "");
    out.started_utc = j.value("started_utc", "");
    out.ended_utc = j.value("ended_utc", "");
    out.overall_status = j.value("overall_status", "");
    out.modules.clear();
    if (j.contains("modules") && j["modules"].is_array()) {
        for (const auto& jm : j["modules"]) {
            ModuleResult m;
            m.module_id = jm.value("module_id", "");
            m.module_version = jm.value("module_version", "1.0.0");
            m.applicable = jm.value("applicable", true);
            m.unsupported_reason = jm.value("unsupported_reason", "");
            for (const auto& x : jm.value("planned_sources", std::vector<std::string>{})) m.planned_sources.push_back(x);
            for (const auto& x : jm.value("checked_sources", std::vector<std::string>{})) m.checked_sources.push_back(x);
            for (const auto& x : jm.value("omitted_sources", std::vector<std::string>{})) m.omitted_sources.push_back(x);
            const std::string st = jm.value("status", "ERROR");
            if      (st == "PASS") m.status = ModuleStatus::PASS;
            else if (st == "PERMISSION_DENIED") m.status = ModuleStatus::PERMISSION_DENIED;
            else if (st == "UNSUPPORTED") m.status = ModuleStatus::UNSUPPORTED;
            else if (st == "TIMEOUT") m.status = ModuleStatus::TIMEOUT;
            else if (st == "SKIPPED") m.status = ModuleStatus::SKIPPED;
            else if (st == "PENDING") m.status = ModuleStatus::PENDING;
            else if (st == "RUNNING") m.status = ModuleStatus::RUNNING;
            else m.status = ModuleStatus::ERROR;
            for (const auto& x : jm.value("errors", std::vector<std::string>{})) m.errors.push_back(x);
            m.elapsed_ms = jm.value("elapsed_ms", 0.0);
            m.has_findings = jm.value("has_findings", false);
            for (const auto& x : jm.value("evidence_ids", std::vector<std::string>{})) m.evidence_ids.push_back(x);
            for (const auto& x : jm.value("finding_ids", std::vector<std::string>{})) m.finding_ids.push_back(x);
            m.status_note = jm.value("status_note", "");
            out.modules.push_back(m);
        }
    }
    return true;
}

} // namespace ctfir
