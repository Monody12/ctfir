// 修复引擎执行器（ADR-009）：原生操作（hosts 删行 / Linux 注释行 / 文件隔离）
// 与命令执行、备份、日志的落地实现——由 CLI 调用。
#pragma once
#include "core/session.hpp"
#include "core/remediate.hpp"

#include <string>
#include <vector>

namespace ctfir {

struct FixContext {
    std::string session_dir;              // fix-backup/ 与 fix-journal.jsonl 所在
    std::string backup_dir;               // session/fix-backup
    bool dry_run = false;
    bool assume_yes = false;
    int executed = 0, skipped = 0, unsupported = 0;
};

// 执行单条 finding 的修复计划（含确认/备份/日志/原生操作）。
// 返回：true=已执行修复（或 dry-run 打印）。
bool run_remediation(const Finding& f, const RemediationPlan& plan, FixContext& fx);

} // namespace ctfir
