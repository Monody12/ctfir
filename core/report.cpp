#include "report.hpp"
#include "util.hpp"
#include "triage.hpp"
#include "display_action.hpp"
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
        p.text = instantiate_advice(f);
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
    std::string color = "#64748B", label = sev;
    if (sev == "high") { color = "#E11D48"; label = "高"; }
    else if (sev == "medium") { color = "#D97706"; label = "中"; }
    else if (sev == "low") { color = "#CA8A04"; label = "低"; }
    else if (sev == "info") { color = "#64748B"; label = "信息"; }
    return "<span class=\"badge\" style=\"background:" + color + "\">" + escape_html(label) + "</span>";
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
    std::map<std::string, const AdvicePair*> adv_by_id;
    for (const auto& a : advices) adv_by_id[a.finding_id] = &a;

    KpiCounts kpi = count_kpi(fds);
    auto order = sorted_finding_indices(fds);

    std::ostringstream h;
    h << "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n"
      << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
      << "<title>ctfir 处置工作台</title>\n<style>\n"
         "html{box-sizing:border-box}*,*:before,*:after{box-sizing:inherit}\n"
         "body{margin:0;background:#E8EEF4;color:#0F172A;font-family:'Segoe UI','Microsoft YaHei UI','Microsoft YaHei',sans-serif;line-height:1.55}\n"
         "a{color:#2563EB;text-decoration:none}a:hover{text-decoration:underline}\n"
         ".top{background:linear-gradient(135deg,#0B1F38 0%,#143656 58%,#1F4E79 100%);color:#fff;padding:20px 28px 16px;box-shadow:0 8px 24px rgba(11,31,56,.28)}\n"
         ".top h1{margin:0;font-size:22px;font-weight:650;letter-spacing:.02em}\n"
         ".top .meta{opacity:.82;font-size:12px;margin-top:6px}\n"
         ".ro{display:inline-block;background:#38BDF8;color:#0B1F38;border-radius:999px;padding:2px 10px;font-size:11px;margin-left:10px;font-weight:700}\n"
         ".wrap{max-width:1240px;margin:0 auto;padding:18px 20px 56px}\n"
         ".kpi{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 0}\n"
         ".chip{display:inline-block;background:rgba(255,255,255,.12);color:#fff;border:1px solid rgba(255,255,255,.18);border-radius:10px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer}\n"
         ".chip:hover{background:rgba(255,255,255,.22)}\n"
         ".chip b{display:block;font-size:20px;line-height:1.1;color:#FDE68A}\n"
         ".chip.inv b{color:#CBD5E1}\n"
         ".toolbar{position:sticky;top:0;z-index:9;background:rgba(232,238,244,.92);padding:12px 0;border-bottom:1px solid #D5DEE8;margin:0 -4px 12px;padding-left:4px}\n"
         ".toolbar input,.toolbar select,.toolbar button{font-size:13px;padding:7px 11px;margin:0 8px 6px 0;border:1px solid #C5D0DC;border-radius:8px;background:#fff}\n"
         ".toolbar button{cursor:pointer;background:#0B1F38;color:#fff;border:0}\n"
         ".toolbar button:hover{background:#143656}\n"
         ".shown{float:right;color:#64748B;font-size:12px;margin-top:8px}\n"
         "h2{font-size:17px;margin:26px 0 10px;color:#0B1F38}\n"
         "table{border-collapse:separate;border-spacing:0;width:100%;font-size:13px;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 1px 2px rgba(11,31,56,.06),0 8px 24px rgba(11,31,56,.04)}\n"
         "th,td{border-bottom:1px solid #E8EEF4;padding:9px 12px;text-align:left;vertical-align:top}\n"
         "th{background:#0B1F38;color:#fff;font-weight:600;position:sticky;top:52px;z-index:2}\n"
         "tr.qrow:hover td{background:#F0F7FF}\n"
         "tr.qrow:nth-child(even) td{background:#F8FAFC}\n"
         "tr.qrow:nth-child(even):hover td{background:#E8F1FF}\n"
         "code,pre,.cmd,.mono{font-family:Consolas,'Courier New',monospace}\n"
         ".cmd{background:#0B1220;color:#E2E8F0;padding:10px 12px;border-radius:8px;display:block;white-space:pre-wrap;word-break:break-all;font-size:12px}\n"
         ".mini{background:#0B1220;color:#E2E8F0;padding:6px 8px;border-radius:6px;display:block;white-space:pre-wrap;word-break:break-all;font-size:11px}\n"
         ".copy{margin-top:6px;font-size:11px;padding:3px 8px;border:0;border-radius:6px;background:#2563EB;color:#fff;cursor:pointer}\n"
         ".card{background:#fff;border-radius:12px;padding:16px 18px;margin:12px 0;box-shadow:0 1px 2px rgba(11,31,56,.06);border-left:5px solid #64748B}\n"
         ".card.sev-high{border-left-color:#E11D48}\n"
         ".card.sev-medium{border-left-color:#D97706}\n"
         ".card.sev-low{border-left-color:#CA8A04}\n"
         ".card.sev-info{border-left-color:#64748B}\n"
         ".meta{color:#64748B;font-size:12px}\n"
         "pre{background:#F1F5F9;border:1px solid #E2E8F0;padding:8px;white-space:pre-wrap;word-break:break-all;font-size:12px;border-radius:8px}\n"
         ".warn{background:#FFF7ED;border:1px solid #FDBA74;padding:12px 14px;border-radius:10px;font-size:13px}\n"
         ".contest{background:#FEF2F2;border:1px solid #FECACA;color:#9F1239;padding:8px 10px;border-radius:8px;font-size:12px;margin:8px 0}\n"
         ".advice{background:#EFF6FF;border:1px solid #BFDBFE;padding:10px 12px;border-radius:8px;white-space:pre-wrap;font-size:13px}\n"
         ".badge{color:#fff;padding:1px 8px;border-radius:999px;font-size:12px;margin-right:6px}\n"
         "details{margin:12px 0}details>summary{cursor:pointer;color:#0B1F38;font-weight:600}\n"
         ".qrow td:nth-child(6){max-width:460px;word-break:break-all}\n"
         "</style>\n"
         "<script>\n"
         "function copyText(t){\n"
         "  var ta=document.createElement('textarea');\n"
         "  ta.value=t||'';\n"
         "  ta.style.position='fixed';ta.style.left='-9999px';\n"
         "  document.body.appendChild(ta);ta.select();\n"
         "  try{document.execCommand('copy');}catch(e){}\n"
         "  document.body.removeChild(ta);\n"
         "}\n"
         "function copyAttr(btn){copyText(btn.getAttribute('data-cmd')||'');btn.innerHTML='已复制';}\n"
         "function setCat(c){\n"
         "  var el=document.getElementById('cat'); if(el) el.value=c;\n"
         "  if(c==='inventory'||c==='all'){var v=document.getElementById('view'); if(v) v.value='all';}\n"
         "  applyFilter();\n"
         "}\n"
         "function applyFilter(){\n"
         "  var qel=document.getElementById('q'); var sel=document.getElementById('sev');\n"
         "  var vel=document.getElementById('view'); var cel=document.getElementById('cat');\n"
         "  var q=qel?qel.value.toLowerCase():'';\n"
         "  var sev=sel?sel.value:'all';\n"
         "  var view=vel?vel.value:'personal';\n"
         "  var cat=cel?cel.value:'all';\n"
         "  var cards=document.getElementsByClassName('fcard');\n"
         "  var rows=document.getElementsByClassName('qrow');\n"
         "  var n=0;\n"
         "  for(var i=0;i<cards.length;i++){\n"
         "    var el=cards[i];\n"
         "    var okSev=(sev==='all')||(el.getAttribute('data-sev')===sev);\n"
         "    var buck=el.getAttribute('data-bucket');\n"
         "    var okView=(view==='all')||(buck!=='inventory');\n"
         "    var okCat=(cat==='all')||(buck===cat);\n"
         "    var txt=(el.textContent||'').toLowerCase();\n"
         "    var okQ=(q==='')||(txt.indexOf(q)>=0);\n"
         "    var show=okSev&&okView&&okCat&&okQ;\n"
         "    el.style.display=show?'':'none';\n"
         "    if(show) n++;\n"
         "  }\n"
         "  for(var j=0;j<rows.length;j++){\n"
         "    var r=rows[j];\n"
         "    var okSev2=(sev==='all')||(r.getAttribute('data-sev')===sev);\n"
         "    var buck2=r.getAttribute('data-bucket');\n"
         "    var okView2=(view==='all')||(buck2!=='inventory');\n"
         "    var okCat2=(cat==='all')||(buck2===cat);\n"
         "    var txt2=(r.textContent||'').toLowerCase();\n"
         "    var okQ2=(q==='')||(txt2.indexOf(q)>=0);\n"
         "    r.style.display=(okSev2&&okView2&&okCat2&&okQ2)?'':'none';\n"
         "  }\n"
         "  var sh=document.getElementById('shown');\n"
         "  if(sh) sh.innerHTML='显示 '+n+' 条';\n"
         "}\n"
         "function collapseAll(v){\n"
         "  var blocks=document.getElementsByClassName('evblock');\n"
         "  for(var i=0;i<blocks.length;i++) blocks[i].style.display=v?'none':'';\n"
         "}\n"
         "</script>\n</head>\n<body>\n";

    h << "<div class=\"top\"><h1>ctfir 只读应急 · 处置工作台"
      << "<span class=\"ro\">只读 · 不执行</span></h1>\n"
      << "<div class=\"meta\">会话 " << escape_html(s.session_id)
      << " ｜ 工具 v" << escape_html(s.tool_version)
      << " ｜ 规则包 v" << escape_html(s.rule_pack_version)
      << " ｜ 生成 " << escape_html(generated_beijing) << "</div>\n"
      << "<div class=\"meta\">主机 " << escape_html(s.os_name) << " " << escape_html(s.os_version)
      << " [" << escape_html(s.os_arch) << "] ｜ 权限 " << escape_html(s.privilege)
      << " ｜ " << escape_html(beijing_time_str(s.started_utc))
      << " → " << escape_html(beijing_time_str(s.ended_utc))
      << " ｜ 状态 <b>" << escape_html(s.overall_status) << "</b></div>\n"
      << "<div class=\"kpi\">"
      << "<span class=\"chip\" onclick=\"setCat('clear')\">立刻清 <b>" << kpi.clear << "</b></span>"
      << "<span class=\"chip\" onclick=\"setCat('harden')\">再加固 <b>" << kpi.harden << "</b></span>"
      << "<span class=\"chip\" onclick=\"setCat('trace')\">溯源 <b>" << kpi.trace << "</b></span>"
      << "<span class=\"chip\" onclick=\"setCat('web')\">Web/中间件 <b>" << kpi.web << "</b></span>"
      << "<span class=\"chip inv\" onclick=\"setCat('inventory')\">已隐藏清单 <b>" << kpi.inventory << "</b></span>"
      << "<span class=\"chip inv\" onclick=\"setCat('all')\">合计 <b>" << kpi.total << "</b></span>"
      << "</div></div>\n";

    h << "<div class=\"wrap\">\n";
    h << "<div class=\"toolbar\">视图 <select id=\"view\" onchange=\"applyFilter()\">"
         "<option value=\"personal\">个人防护</option>"
         "<option value=\"team\">团队综合</option>"
         "<option value=\"all\">全部</option></select>"
         "类别 <select id=\"cat\" onchange=\"applyFilter()\">"
         "<option value=\"all\">全部类别</option>"
         "<option value=\"clear\">立刻清</option>"
         "<option value=\"harden\">再加固</option>"
         "<option value=\"trace\">溯源</option>"
         "<option value=\"web\">Web/中间件</option>"
         "<option value=\"inventory\">清单/事实</option></select>"
         "风险 <select id=\"sev\" onchange=\"applyFilter()\">"
         "<option value=\"all\">全部</option><option value=\"high\">高</option>"
         "<option value=\"medium\">中</option><option value=\"low\">低</option>"
         "<option value=\"info\">信息</option></select>"
         "搜索 <input id=\"q\" oninput=\"applyFilter()\" placeholder=\"标题 / 对象 / 规则 / 依据\">"
         "<button type=\"button\" onclick=\"collapseAll(true)\">折叠证据</button>"
         "<button type=\"button\" onclick=\"collapseAll(false)\">展开证据</button>"
         "<span class=\"shown\" id=\"shown\"></span></div>\n";

    h << "<div class=\"warn\">本报告为<b>只读扫描</b>结果：PASS 仅表示声明范围内未命中，"
         "不代表系统安全。建议仅供复制，工具不修改系统。"
         "个人赛先清「立刻清」再做「再加固」。团队赛（安全实操 / AI 综合防御）请核 Web、日志、中间件；"
         "切「全部」找回账户清单等事实项。";
    if (kpi.web == 0)
        h << " 当前 Web/中间件 = 0，不代表无站点。";
    h << "</div>\n";

    h << "<h2>处置清单</h2>\n"
         "<table><tr><th>#</th><th>优先级</th><th>风险</th><th>问题</th><th>对象</th><th>一条命令</th></tr>\n";
    int qn = 0;
    for (size_t n = 0; n < order.size(); ++n) {
        const Finding& f = fds[order[n]];
        Triage t = triage_of(f);
        DisplayAction da = display_action(f);
        ++qn;
        h << "<tr class=\"qrow\" data-sev=\"" << escape_html(f.severity)
          << "\" data-bucket=\"" << t.bucket_id << "\""
          << (t.default_visible ? "" : " style=\"display:none\"")
          << "><td>" << qn << "</td><td>" << escape_html(t.bucket_zh)
          << "</td><td>" << sev_badge(f.severity)
          << "</td><td><a href=\"#f" << order[n] << "\">" << escape_html(da.title)
          << "</a></td><td class=\"meta\">" << escape_html(f.object_ref)
          << "</td><td><span class=\"mini\">" << escape_html(da.command)
          << "</span><button type=\"button\" class=\"copy\" data-cmd=\""
          << escape_html(da.command) << "\" onclick=\"copyAttr(this)\">复制</button></td></tr>\n";
    }
    if (fds.empty())
        h << "<tr><td colspan=\"6\">声明范围内未命中规则。这不等于系统安全。</td></tr>\n";
    h << "</table>\n";

    h << "<h2>发现详情（" << fds.size() << "）</h2>\n";
    for (size_t n = 0; n < order.size(); ++n) {
        size_t i = order[n];
        const Finding& f = fds[i];
        Triage t = triage_of(f);
        DisplayAction da = display_action(f);
        h << "<div class=\"card fcard sev-" << escape_html(f.severity)
          << "\" id=\"f" << i << "\" data-sev=\"" << escape_html(f.severity)
          << "\" data-bucket=\"" << t.bucket_id << "\""
          << (t.default_visible ? "" : " style=\"display:none\"")
          << "><p><b>" << escape_html(da.title) << "</b> "
          << sev_badge(f.severity)
          << " <span class=\"badge\" style=\"background:#0F2744\">" << escape_html(t.bucket_zh) << "</span>"
          << " <span class=\"meta\">" << escape_html(f.rule_id)
          << " ｜ 置信度 " << escape_html(f.confidence)
          << " ｜ " << escape_html(f.finding_id) << "</span></p>\n";
        h << "<p><b>依据：</b>" << escape_html(f.rationale) << "</p>\n";
        if (!f.object_ref.empty())
            h << "<p class=\"meta\">位置：" << escape_html(f.object_ref) << "</p>\n";
        h << "<p class=\"cmd\">" << escape_html(da.command) << "</p>\n"
          << "<button type=\"button\" class=\"copy\" data-cmd=\"" << escape_html(da.command)
          << "\" onclick=\"copyAttr(this)\">复制命令</button>\n";
        if (!da.contest_note.empty())
            h << "<div class=\"contest\">" << escape_html(da.contest_note) << "</div>\n";
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
        auto ait = adv_by_id.find(f.finding_id);
        if (ait != adv_by_id.end())
            h << "<div class=\"advice\"><b>建议（复制参考，工具不执行）：</b>\n"
              << escape_html(ait->second->text) << "</div>\n";
        h << "</div>\n";
    }

    h << "<details><summary>模块总览</summary>\n<table><tr><th>模块</th><th>状态</th><th>完成/计划来源</th><th>耗时</th><th>线索</th><th>说明</th></tr>\n";
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
    h << "</table></details>\n";

    h << "<details><summary>未完成检查（不充当安全）</summary>\n<table><tr><th>模块</th><th>状态</th><th>原因</th></tr>\n";
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
    h << "</table></details>\n";

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
            h << "<details><summary>时间线（" << lines.size() << "）</summary>\n<pre>";
            size_t shown = 0;
            for (const auto& l : lines) {
                if (++shown > 300) { h << "...[超 300 条截断]\n"; break; }
                h << escape_html(l) << "\n";
            }
            h << "</pre></details>\n";
        }
    }

    h << "<details><summary>证据清单（" << ev.size() << "）</summary>\n<table><tr><th>ID</th><th>来源</th><th>位置</th><th>访问</th><th>SHA256</th><th>留证文件</th></tr>\n";
    for (const auto& e : ev) {
        h << "<tr><td class=\"meta\">" << escape_html(e.evidence_id) << "</td><td>" << escape_html(e.collector)
          << "</td><td class=\"meta\">" << escape_html(e.source_path)
          << (e.line_context.empty() ? "" : " @" + escape_html(e.line_context))
          << "</td><td>" << escape_html(e.access_status)
          << "</td><td class=\"meta\">" << escape_html(e.sha256.substr(0, 16)) << "…"
          << "</td><td class=\"meta\">" << escape_html(e.raw_ref) << "</td></tr>\n";
    }
    h << "</table></details>\n";

    h << "<p class=\"meta\">ctfir 只读应急助手 · 离线报告（无外部资源；内联脚本仅筛选） · MIT License · "
         "时间均为北京时间（UTC+8）。</p>\n</div>\n</body></html>\n";
    return h.str();
}

} // namespace ctfir
