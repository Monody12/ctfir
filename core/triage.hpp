#pragma once
// 处置工作台：分桶 / 中文标题 / 默认可见性 / 排序（纯展示，不改 findings）
#include "model.hpp"

#include <string>
#include <vector>
#include <cstddef>

namespace ctfir {

enum class Bucket {
    Clear,      // 立刻清
    Harden,     // 再加固
    Trace,      // 溯源
    Web,        // Web/中间件
    Inventory   // 清单/事实（默认隐藏）
};

enum class ViewPreset {
    Personal,   // 个人防护：隐藏 inventory
    Team,       // 团队综合：同个人（Web 命中本就可见）
    All         // 全部
};

struct Triage {
    Bucket bucket = Bucket::Trace;
    const char* bucket_id;     // clear/harden/trace/web/inventory
    const char* bucket_zh;     // 立刻清/...
    std::string title_zh;
    bool default_visible = true;
};

const char* bucket_id(Bucket b);
const char* bucket_zh(Bucket b);
int bucket_rank(Bucket b);          // 立刻清=0 … 清单=4
int severity_rank(const std::string& sev);
int confidence_rank(const std::string& conf);

Bucket bucket_of(const std::string& rule_id);
Bucket bucket_of(const Finding& f); // 含微软预装 Active Setup → 清单
bool is_known_ms_activesetup(const std::string& object_ref);
std::string title_zh_of(const Finding& f);
Triage triage_of(const Finding& f);

ViewPreset parse_view_preset(const std::string& s); // personal/team/all
bool finding_visible(const Finding& f, ViewPreset view,
                     const std::string& cat,   // all / clear / ...
                     const std::string& sev,   // all / high / ...
                     const std::string& query);

// 默认排序：桶 → 风险 → 置信度 → rule_id；返回下标
std::vector<std::size_t> sorted_finding_indices(const std::vector<Finding>& fds);

struct KpiCounts {
    int clear = 0, harden = 0, trace = 0, web = 0, inventory = 0, total = 0;
};
KpiCounts count_kpi(const std::vector<Finding>& fds);

} // namespace ctfir
