#pragma once
// 建议（Advice）：只生成文本，永不执行（PLAN §9.5）。advice_id 必须在此注册方可挂到 Finding。
#include <string>

namespace ctfir {

struct Advice {
    const char* id;
    const char* title;
    const char* text;   // 七段式：解释/留证/复核/备份/处置/回滚/复查
};

// 未命中返回 nullptr
const Advice* find_advice(const std::string& advice_id);

} // namespace ctfir
