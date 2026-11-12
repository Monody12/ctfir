#pragma once
// 数据契约 v1（PLAN §9.1）。所有时间 ISO8601 UTC 存储，展示层转北京时间。
// schema major 不兼容 → 拒绝读取（见 model.cpp load_session）。
#include <string>
#include <vector>
#include <cstdint>

namespace ctfir {

constexpr int kSchemaVersion = 1;
constexpr const char* kToolVersion = "0.6.1";

struct Evidence {
    std::string evidence_id;
    std::string collector;            // module id
    std::string collector_version;
    std::string source_kind;          // file / registry / api / eventlog / command
    std::string source_path;          // 路径或 API 名
    std::string capture_time_utc;
    std::string raw_ref;              // 相对 evidence/ 的原始留证文件（可空）
    std::string sha256;               // 原始内容哈希（文件类）
    std::string object_identity;      // 文件ID/inode/PID+starttime 等身份（尽力）
    std::string access_status;        // ok / denied / not_found / partial / error
    std::string trust;                // live_local / synthetic / unknown
    std::string redaction;            // none / partial
    std::vector<std::string> limitations;
    std::string payload;              // 归一化摘要（文本，报告直接展示）
    std::string line_context;         // 行号/行原文定位（可选，如 "hosts:15"）
};

struct Finding {
    std::string finding_id;
    std::string rule_id;              // 如 LNX.ACC.UID0.001
    std::string rule_version;
    std::string platform;             // windows / linux
    std::vector<std::string> evidence_ids;
    std::vector<std::string> evidence_paths;
    std::string object_ref;          // 对象定位（文件:行 / 注册表路径 / PID 等）
    std::string rationale;            // 中文解释
    std::string severity;             // info / low / medium / high
    std::string confidence;           // low / medium / high
    std::string evidence_trust;       // live_local / synthetic / unknown
    std::string status = "FINDING";
    std::vector<std::string> limitations;
    std::string advice_id;
};

enum class ModuleStatus {
    PASS, PERMISSION_DENIED, UNSUPPORTED, TIMEOUT, ERROR, SKIPPED, PENDING, RUNNING
};
const char* module_status_str(ModuleStatus s);
bool module_status_terminal(ModuleStatus s); // 终态判定（PENDING/RUNNING 非终态）
// 规则：FINDING 通过 findings 非空表达（见 ModuleResult::has_findings），
// 因此终态枚举不含 FINDING——命中结果的模块 status=PASS 且 findings 非空，
// 与 PLAN §9.2 的差异在此显式声明（finding 不作为"模块失败"计）。

struct ModuleResult {
    std::string module_id;
    std::string module_version = "1.0.0";
    bool applicable = true;
    std::string unsupported_reason;   // not_applicable / capability_missing
    std::vector<std::string> planned_sources;
    std::vector<std::string> checked_sources;
    std::vector<std::string> omitted_sources;  // 逐项注明原因（denied/budget/...）
    ModuleStatus status = ModuleStatus::PENDING;
    std::vector<std::string> errors;  // 含错误码/errno/win32 码
    double elapsed_ms = 0;
    bool has_findings = false;
    std::vector<std::string> evidence_ids;
    std::vector<std::string> finding_ids;
    std::string status_note;          // 人读状态补充
};

struct ScanSession {
    int schema_version = kSchemaVersion;
    std::string session_id;
    std::string tool_version = kToolVersion;
    std::string rule_pack_version = "6.0.1";
    std::string os_name, os_version, os_arch, privilege;
    std::string profile = "ctf";
    std::string started_utc, ended_utc;
    std::string overall_status;       // COMPLETE / PARTIAL / CANCELLED / FAILED
    std::vector<ModuleResult> modules;
    std::string platform_;            // 运行期内部字段：当前模块平台（不入库）
};

// —— JSON 序列化（nlohmann 单头）——
std::string evidence_to_json(const Evidence&);
std::string finding_to_json(const Finding&);
std::string module_result_to_json(const ModuleResult&);
std::string session_to_json(const ScanSession&);
// 读取并校验 schema_version：major≠1 → 返回 false 且填 reason（拒绝读取）
bool session_from_json(const std::string& json_text, ScanSession& out, std::string& reason);
// 会话目录装载（findings.json / evidence.json 数组；解析失败 false + reason）
bool findings_from_json(const std::string& text, std::vector<Finding>& out, std::string& reason);
bool evidence_from_json(const std::string& text, std::vector<Evidence>& out, std::string& reason);

} // namespace ctfir
