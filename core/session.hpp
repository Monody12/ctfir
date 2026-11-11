#pragma once
// 会话与调度（PLAN §9.2 状态机；PLAN §11.3 纪律）。
// 顺序执行模块；每模块预算（默认 30s）；用户取消保留 partial；JSONL 事件流式落盘；
// 汇总文件原子替换；任何模块失败不阻断其他模块。
#include "model.hpp"
#include "evidence.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <vector>

namespace ctfir {

struct ScanConfig {
    std::string out_dir;                 // 必须已存在可写（run 前校验）
    long long module_budget_ms = 30000;  // 每模块默认预算
    bool save_raw_evidence = true;
    std::vector<std::string> extra_dirs; // 用户附加巡检目录（--dir）
    std::string baseline_path;           // SHA256 基线清单（--baseline，"路径 sha256" 每行）
    std::string profile = "full";        // quick / full / web
};

class Session;

class ModuleCtx {
public:
    ModuleCtx(Session& s, ModuleResult& mr, std::atomic<bool>& cancel,
              std::chrono::steady_clock::time_point deadline, long long budget_ms);

    bool cancelled() const;
    bool expired() const;            // 预算到期（模块应尽快收尾并置 TIMEOUT）
    long long remaining_ms() const;
    long long budget_ms() const { return budget_ms_; }
    void request_cancel();           // 模块内触发用户取消（同一标志，保留 partial）

    void set_status(ModuleStatus st);
    void note(const std::string& s);                 // status_note 追加（分号连接）
    void error(const std::string& code_and_msg);     // errors 追加
    void planned_source(const std::string& src);
    void checked_source(const std::string& src);
    void omitted_source(const std::string& src, const std::string& reason);

    std::string add_evidence(Evidence e); // 自动补 id/时间/collector/信任度；sanitize_utf8；返回 evidence_id
    void add_finding(Finding f);       // 自动补 id/platform/status；advice_id 存在性校验
    std::string save_raw(const std::string& content, const std::string& suggested_name,
                         std::string& sha_out); // 写 evidence/，返回相对路径；失败返回 ""

    const ScanConfig& config() const;

private:
    Session& s_;
    ModuleResult& mr_;
    std::atomic<bool>& cancel_;
    std::chrono::steady_clock::time_point deadline_;
    long long budget_ms_;
    size_t evidence_base_, finding_base_;
};

class Session {
public:
    explicit Session(ScanConfig cfg);

    void set_host_info(const std::string& os_name, const std::string& os_version,
                       const std::string& os_arch, const std::string& privilege);

    struct ModuleDef {
        std::string id;
        std::string version = "1.0.0";
        std::string platform;   // windows / linux
        // 模块通过 ctx 写状态/来源/证据/发现；引擎保证终态兜底
        std::function<void(ModuleCtx&)> fn;
    };

    // out_dir 不可写 → 返回 false 且填 reason（会话 FAILED，不开始扫描）
    bool prepare_out_dir(std::string& reason);
    void run(const std::vector<ModuleDef>& mods);

    void request_cancel() { cancel_ = true; }
    bool cancelled() const { return cancel_; }

    // UI 实时钩子：event(name, module_id, detail)；可在 run() 前设置（线程安全由使用方保证）
    std::function<void(const std::string&, const std::string&, const std::string&)> event_hook;

    const ScanSession& session() const { return s_; }
    const std::vector<Evidence>& evidence() const { return evidence_; }
    const std::vector<Finding>& findings() const { return findings_; }
    const ScanConfig& config() const { return cfg_; }
    void set_profile(const std::string& p) { s_.profile = p; }

    // 产出目录文件：session.json / module-results.json / findings.json / advice.json /
    // events.jsonl / integrity.sha256 / evidence/*.raw
    bool write_outputs(std::string& err);

private:
    friend class ModuleCtx;
    void event(const std::string& name, const std::string& module_id, const std::string& detail);

    ScanConfig cfg_;
    ScanSession s_;
    std::vector<Evidence> evidence_;
    std::vector<Finding> findings_;
    std::vector<std::string> advice_lines_;  // finding_id → advice 文本（与 findings 对齐）
    std::atomic<bool> cancel_{false};
    void* events_stream_ = nullptr;          // std::ofstream*（避免头文件依赖 fstream）
};

} // namespace ctfir
