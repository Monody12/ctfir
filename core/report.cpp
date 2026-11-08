#include "report.hpp"
#include "util.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <map>
#include <sstream>

namespace ctfir {

using nlohmann::json;

std::vector<AdvicePair> advices_for(const std::vector<Finding>& fds) {
    std::vector<AdvicePair> out;
    for (const auto& f : fds) {
        AdvicePair p;
        p.finding_id = f.finding_id;
        p.advice_id = f.advice_id;
        const Advice* a = find_advice(f.advice_id);
        if (a) {
            p.text = std::string("【") + a->title + "】\n" + a->text;
        } else {
            p.text = "（该发现未挂接建议：请依据证据原文人工复核；本工具不执行任何修改。）";
        }
        out.push_back(std::move(p));
    }
    return out;
}

std::string build_json_report(const ScanSession& s,
                              const std::vector<Evidence>& ev,
                              const std::vector<Finding>& fds,
                              const std::vector<AdvicePair>& advices) {
    json j;
    j["schema_version"] = kSchemaVersion;
    j["session"] = json::parse(session_to_json(s));
    j["evidence"] = json::array();
    for (const auto& e : ev) j["evidence"].push_back(json::parse(evidence_to_json(e)));
    j["findings"] = json::array();
    for (const auto& f : fds) j["findings"].push_back(json::parse(finding_to_json(f)));
    j["advice"] = json::array();
    for (const auto& a : advices) {
        j["advice"].push_back({{"finding_id", a.finding_id},
                               {"advice_id", a.advice_id},
                               {"never_auto_execute", true},
                               {"text", a.text}});
    }
    j["disclaimer"] = "只读扫描结果。PASS 仅指声明范围内未命中，不代表系统安全；受限/失败项已如实列出。";
    return j.dump(2);
}

static std::string sev_badge(const std::string& sev) {
    std::string color = "#888";
    if (sev == "high") color = "#c62828";
    else if (sev == "medium") color = "#ef6c00";
    else if (sev == "low") color = "#f9a825";
    else if (sev == "info") color = "#2e7d32";
    return "<span style=\"background:" + color + ";color:#fff;padding:1px 8px;border-radius:3px;font-size:12px\">" +
           escape_html(sev) + "</span>";
}

static std::string status_text(const ModuleResult& m) {
    std::string t = module_status_str(m.status);
    if (m.status == ModuleStatus::UNSUPPORTED && !m.unsupported_reason.empty())
        t += " (" + m.unsupported_reason + ")";
    return t;
}

std::string build_html_report(const ScanSession& s,
                              const std::vector<Evidence>& ev,
                              const std::vector<Finding>& fds,
                              const std::vector<AdvicePair>& advices,
                              const std::string& generated_beijing) {
    std::map<std::string, const Evidence*> ev_by_id;
    for (const auto& e : ev) ev_by_id[e.evidence_id] = &e;

    std::ostringstream h;
    h << "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n"
      << "<title>ctfir 只读扫描报告</title>\n<style>\n"
         "body{font-family:'Microsoft YaHei',sans-serif;margin:24px;max-width:1100px;color:#222;line-height:1.6}\n"
         "h1{font-size:22px;border-bottom:2px solid #345;padding-bottom:6px}\n"
         "h2{font-size:17px;margin-top:28px;border-left:4px solid #345;padding-left:8px}\n"
         "table{border-collapse:collapse;width:100%;font-size:13px}\n"
         "th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}\n"
         "th{background:#f0f2f5}\n"
         ".card{border:1px solid #ddd;border-radius:6px;padding:12px 14px;margin:12px 0;background:#fafafa}\n"
         ".meta{color:#555;font-size:12px}\n"
         "pre{background:#f4f4f4;border:1px solid #e0e0e0;padding:8px;white-space:pre-wrap;word-break:break-all;font-size:12px}\n"
         ".warn{background:#fff8e1;border:1px solid #ffe082;padding:8px 12px;border-radius:4px;font-size:13px}\n"
         ".ok{color:#2e7d32}.bad{color:#c62828}\n"
         ".advice{background:#eef3ff;border:1px solid #c5cae9;padding:8px 12px;border-radius:4px;white-space:pre-wrap;font-size:13px}\n"
         ".toolbar{position:sticky;top:0;background:#fff;padding:6px 0;border-bottom:1px solid #eee;z-index:9}\n"
         ".toolbar input,.toolbar button{font-size:13px;padding:3px 8px;margin-right:6px}\n"
         "</style>\n"
      // 内联 vanilla JS（零外部资源）：严重度筛选 + 文本搜索 + 折叠
      << "<script>\n"
         "function applyFilter(){\n"
         "  var q=document.getElementById('q').value.toLowerCase();\n"
         "  var sev=document.getElementById('sev').value;\n"
         "  document.querySelectorAll('.fcard').forEach(function(el){\n"
         "    var okSev=(sev==='all')||(el.getAttribute('data-sev')===sev);\n"
         "    var okQ=(q==='')||(el.textContent.toLowerCase().indexOf(q)>=0);\n"
         "    el.style.display=(okSev&&okQ)?'':'none';\n"
         "  });\n"
         "}\n"
         "function collapseAll(v){document.querySelectorAll('.fcard .evblock').forEach(function(el){el.style.display=v?'none':'';});}\n"
         "</script>\n"
      << "</head>\n<body>\n";

    h << "<div class=\"toolbar\">筛选: <select id=\"sev\" onchange=\"applyFilter()\">"
         "<option value=\"all\">全部</option><option value=\"high\">high</option>"
         "<option value=\"medium\">medium</option><option value=\"low\">low</option>"
         "<option value=\"info\">info</option></select>"
         "搜索: <input id=\"q\" oninput=\"applyFilter()\" placeholder=\"规则/位置/依据…\">"
         "<button onclick=\"collapseAll(true)\">折叠证据</button>"
         "<button onclick=\"collapseAll(false)\">展开证据</button></div>\n";

    h << "<h1>ctfir 只读应急扫描报告</h1>\n";
    h << "<p class=\"meta\">会话 " << escape_html(s.session_id)
      << " ｜ 工具 v" << escape_html(s.tool_version)
      << " ｜ 规则包 v" << escape_html(s.rule_pack_version)
      << " ｜ 报告生成：" << escape_html(generated_beijing) << "</p>\n";
    h << "<p class=\"meta\">主机 " << escape_html(s.os_name) << " " << escape_html(s.os_version)
      << " [" << escape_html(s.os_arch) << "] ｜ 权限：" << escape_html(s.privilege)
      << " ｜ 开始 " << escape_html(beijing_time_str(s.started_utc))
      << " ｜ 结束 " << escape_html(beijing_time_str(s.ended_utc))
      << " ｜ 会话状态 <b>" << escape_html(s.overall_status) << "</b></p>\n";

    h << "<div class=\"warn\">本报告为<b>只读扫描</b>结果：任何 PASS 仅表示声明范围内未命中，"
         "不代表系统安全；受限/失败/未覆盖项如实列出。报告不含任何网络资源；建议仅供复制参考，工具不执行任何修改。</div>\n";

    // —— 模块表 ——
    h << "<h2>模块总览</h2>\n<table><tr><th>模块</th><th>状态</th><th>完成/计划来源</th><th>耗时</th><th>线索</th><th>说明</th></tr>\n";
    for (const auto& m : s.modules) {
        h << "<tr><td>" << escape_html(m.module_id) << "</td><td>" << escape_html(status_text(m))
          << "</td><td>" << m.checked_sources.size() << "/" << m.planned_sources.size()
          << (m.omitted_sources.empty() ? "" : ("（漏 " + std::to_string(m.omitted_sources.size()) + "）"))
          << "</td><td>" << static_cast<long long>(m.elapsed_ms) << "ms</td><td>"
          << (m.has_findings ? "有" : "-") << "</td><td class=\"meta\">"
          << escape_html(m.status_note);
        for (const auto& o : m.omitted_sources) h << "<br>漏项: " << escape_html(o);
        for (const auto& e2 : m.errors) h << "<br>错误: " << escape_html(e2);
        h << "</td></tr>\n";
    }
    h << "</table>\n";

    // —— 发现 ——
    h << "<h2>发现（" << fds.size() << "）</h2>\n";
    if (fds.empty()) h << "<p>声明范围内未命中规则。这不等于系统安全（见未完成检查与限制）。</p>\n";
    for (size_t i = 0; i < fds.size(); ++i) {
        const auto& f = fds[i];
        h << "<div class=\"card fcard\" data-sev=\"" << escape_html(f.severity) << "\"><p><b>" << (i + 1) << ". " << escape_html(f.rule_id) << "</b> "
          << sev_badge(f.severity)
          << " <span class=\"meta\">置信度 " << escape_html(f.confidence)
          << " ｜ 证据信任 " << escape_html(f.evidence_trust)
          << " ｜ " << escape_html(f.finding_id) << "</span></p>\n";
        h << "<p><b>依据：</b>" << escape_html(f.rationale) << "</p>\n";
        if (!f.object_ref.empty())
            h << "<p class=\"meta\">位置：" << escape_html(f.object_ref) << "</p>\n";
        if (!f.evidence_paths.empty())
            h << "<p class=\"meta\">来源：" << escape_html(join(f.evidence_paths, " ; ")) << "</p>\n";
        for (const auto& eid : f.evidence_ids) {
            auto it = ev_by_id.find(eid);
            if (it != ev_by_id.end() && !it->second->payload.empty()) {
                h << "<p class=\"meta\">证据 " << escape_html(eid)
                  << "（" << escape_html(it->second->source_path)
                  << (it->second->line_context.empty() ? "" : " @ " + escape_html(it->second->line_context))
                  << "）：</p>\n<pre class=\"evblock\">" << escape_html(it->second->payload) << "</pre>\n";
            }
        }
        if (!f.limitations.empty())
            h << "<p class=\"meta\">限制：" << escape_html(join(f.limitations, "；")) << "</p>\n";
        for (const auto& a : advices) {
            if (a.finding_id == f.finding_id) {
                h << "<div class=\"advice\"><b>建议（复制参考，工具不执行）：</b>\n" << escape_html(a.text) << "</div>\n";
            }
        }
        h << "</div>\n";
    }

    // —— 未完成检查 ——
    h << "<h2>未完成检查（不充当安全）</h2>\n<table><tr><th>模块</th><th>状态</th><th>原因</th></tr>\n";
    bool any = false;
    for (const auto& m : s.modules) {
        if (m.status == ModuleStatus::PASS && !m.has_findings && m.omitted_sources.empty()) continue;
        if (m.status != ModuleStatus::PASS || !m.omitted_sources.empty()) {
            any = true;
            h << "<tr><td>" << escape_html(m.module_id) << "</td><td>" << escape_html(status_text(m))
              << "</td><td class=\"meta\">" << escape_html(m.status_note);
            for (const auto& o : m.omitted_sources) h << "<br>漏项: " << escape_html(o);
            for (const auto& e2 : m.errors) h << "<br>错误: " << escape_html(e2);
            h << "</td></tr>\n";
        }
    }
    if (!any) h << "<tr><td colspan=\"3\">（声明范围内无未完成项）</td></tr>\n";
    h << "</table>\n";

    // —— 时间线（从证据载荷提取日期开头行，排序去重）——
    {
        std::vector<std::string> lines;
        for (const auto& e : ev) {
            for (const auto& l : split_lines(e.payload)) {
                if (l.size() >= 16 && l[4] == '-' && l[7] == '-' && l[10] == ' ' && l[13] == ':')
                    lines.push_back(l);
            }
        }
        std::sort(lines.begin(), lines.end());
        lines.erase(std::unique(lines.begin(), lines.end()), lines.end());
        if (!lines.empty()) {
            h << "<h2>时间线（证据内带时间戳行，升序；" << lines.size() << " 条</h2>\n<pre>";
            size_t shown = 0;
            for (const auto& l : lines) {
                if (++shown > 300) { h << "...[超 300 条截断]\n"; break; }
                h << escape_html(l) << "\n";
            }
            h << "</pre>\n";
        }
    }

    // —— 处置手册（按本次发现涉及类型聚合）——
    {
        std::map<std::string, const Advice*> used;
        for (const auto& f : fds) {
            const Advice* a = find_advice(f.advice_id);
            if (a) used[a->id] = a;
        }
        if (!used.empty()) {
            h << "<h2>处置手册（六步制；全部为文本，工具不执行）</h2>\n";
            for (const auto& [id, a] : used) {
                h << "<div class=\"card\"><p><b>" << escape_html(a->title) << "</b> <span class=\"meta\">"
                  << escape_html(id) << "</span></p>\n<div class=\"advice\">" << escape_html(a->text)
                  << "</div></div>\n";
            }
        }
    }

    // —— 证据清单 ——
    h << "<h2>证据清单（" << ev.size() << "）</h2>\n<table><tr><th>ID</th><th>来源</th><th>位置</th><th>访问</th><th>SHA256</th><th>留证文件</th></tr>\n";
    for (const auto& e : ev) {
        h << "<tr><td class=\"meta\">" << escape_html(e.evidence_id) << "</td><td>" << escape_html(e.collector)
          << "</td><td class=\"meta\">" << escape_html(e.source_path)
          << (e.line_context.empty() ? "" : " @" + escape_html(e.line_context))
          << "</td><td>" << escape_html(e.access_status)
          << "</td><td class=\"meta\">" << escape_html(e.sha256.substr(0, 16)) << "…"
          << "</td><td class=\"meta\">" << escape_html(e.raw_ref) << "</td></tr>\n";
    }
    h << "</table>\n";

    h << "<p class=\"meta\">ctfir 只读应急助手 · 离线报告（无外部资源/无脚本） · MIT License · "
         "本报告时间均为北京时间（UTC+8），原始时间为 UTC。</p>\n";
    h << "</body></html>\n";
    return h.str();
}

} // namespace ctfir
