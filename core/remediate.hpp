#pragma once
// 受控修复（ADR-009，2026-11-12 用户批准）：默认只读不变；
// 仅当用户显式调用 `ctfir fix` 并逐条确认时，执行白名单内的最小处置。
// 每次修复：先备份到会话 fix-backup/，写 fix-journal.jsonl，再执行，再提示复扫。
#include "model.hpp"

#include <string>
#include <vector>

namespace ctfir {

struct RemediationPlan {
    bool supported = false;              // 该规则是否在白名单内
    std::vector<std::string> backups;    // 前置换证/备份命令（只读或落会话目录）
    std::vector<std::string> steps;      // 处置命令（占位符已解析为具体对象）
    std::vector<std::string> native_ops; // 描述内置文件级操作（如 hosts 删行）——由引擎直接执行
    std::string rollback_note;
    std::string reason;                  // unsupported 时的原因
};

// 由 finding 生成修复计划（object_ref/证据已含具体对象；不依赖外部输入）
RemediationPlan plan_remediation(const Finding& f);

} // namespace ctfir
