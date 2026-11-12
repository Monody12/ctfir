#pragma once
// 报告：JSON 终报（单对象）+ 自包含 HTML（零外部资源、全转义、允许内联 JS）。
#include "model.hpp"
#include "session.hpp"
#include "advice.hpp"

#include <string>
#include <vector>

namespace ctfir {

struct AdvicePair {
    std::string finding_id;
    std::string advice_id;
    std::string text;
};

// 单 JSON 对象：{session, modules, evidence, findings, advice}
std::string build_json_report(const ScanSession& s,
                              const std::vector<Evidence>& ev,
                              const std::vector<Finding>& fds,
                              const std::vector<AdvicePair>& advices);

// 自包含 HTML（zh-CN）；generated_beijing 为展示时间
std::string build_html_report(const ScanSession& s,
                              const std::vector<Evidence>& ev,
                              const std::vector<Finding>& fds,
                              const std::vector<AdvicePair>& advices,
                              const std::string& generated_beijing);

// 由 findings 生成 AdvicePair（含未注册 advice 的兜底文本）
std::vector<AdvicePair> advices_for(const std::vector<Finding>& fds);

} // namespace ctfir
