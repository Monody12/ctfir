# -*- coding: utf-8 -*-
# v0.5-R8 最后一批遗漏补齐
import os

BASE = r'C:\Users\Administrator\Documents\zcode-projects\ctfir'

# ============ 1. Win EVTLOG Event 1102 ============
p = os.path.join(BASE, 'platform', 'win', 'mod_w2.cpp')
s = open(p, encoding='utf-8', newline='').read()

# 扩展查询加入 1102
old = "or EventID=4726 or EventID=4732)]]"
new = "or EventID=4726 or EventID=4732 or EventID=1102)]]"
s = s.replace(old, new)

# 变量声明
old = "std::vector<std::string> mgmt_timeline;"
new = "std::vector<std::string> mgmt_timeline;\n    bool log_cleared = false;"
s = s.replace(old, new, 1)

# 解析 1102
old = 'std::string group = xml_data(x, "TargetUserName");'
new = old + '\n            if (eid == 0) { size_t p1 = x.find("<EventID>"); if (p1 != std::string::npos) eid = std::atoi(x.c_str() + p1 + 9); }'
s = s.replace(old, new, 1)

# 在 4732 后添加 1102 处理
old = "mgmt_timeline.push_back(tb + \" 加入组 \" + (member.empty() ? \"?\" : member) + \" → \" + group);"
new = old + "\n            } else if (eid == 1102) {\n                log_cleared = true;\n                mgmt_timeline.push_back(tb + \" 安全日志被清除！\");"
s = s.replace(old, new, 1)

# evidence payload 加 log_cleared
old = '" account_created(4720)=" + std::to_string(created.size()) +'
new = old + '\n                " log_cleared(1102)=" + std::string(log_cleared ? "YES" : "no") +'
s = s.replace(old, new, 1)

# 1102 finding
old = "    if (fail_total >= 20) {"
new = """    if (log_cleared) {
        Finding f;
        f.rule_id = "WIN.EVT.LOGCLEAR.001";
        f.severity = "high";
        f.confidence = "high";
        f.rationale = "安全日志被清除（Event 1102）——攻击者痕迹擦除的强指标";
        f.object_ref = "Security 1102";
        f.advice_id = "ADVICE.EVENTLOG.REVIEW.001";
        ctx.add_finding(f);
    }
    if (fail_total >= 20) {"""
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('1. Event 1102 done')

# ============ 2. Linux .ssh/config ProxyCommand ============
p = os.path.join(BASE, 'platform', 'linux', 'mod_a.cpp')
s = open(p, encoding='utf-8', newline='').read()
old = "// 私钥存在性"
new = """// .ssh/config ProxyCommand 后门
            {
                std::string cfg = home + "/.ssh/config";
                ReadResult cr = read_source(ctx, cfg, false);
                if (cr.ok) {
                    for_each_line(cr.content, [&](int lno, const std::string& l) {
                        std::string tl = trim(l);
                        if (contains_ci(tl, "ProxyCommand") &&
                            (contains_ci(tl, "nc ") || contains_ci(tl, "bash") || contains_ci(tl, "/tmp/"))) {
                            Finding f;
                            f.rule_id = "LNX.SSH.PROXYCMD.001";
                            f.severity = "high";
                            f.confidence = "medium";
                            f.rationale = "SSH config ProxyCommand 含可疑命令: " + tl.substr(0, 150);
                            f.object_ref = cfg + ":" + std::to_string(lno);
                            f.advice_id = "ADVICE.SSHKEY.REVIEW.001";
                            ctx.add_finding(f);
                        }
                    });
                }
            }
            // 私钥存在性"""
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('2. SSH ProxyCommand done')

# ============ 3. Linux /etc/environment PATH ============
p = os.path.join(BASE, 'platform', 'linux', 'mod_e.cpp')
s = open(p, encoding='utf-8', newline='').read()
old = "    ctx.set_status(ModuleStatus::PASS);\n}\n\n} // namespace\n\nvoid register_mods_e"
new = """    // /etc/environment PATH
    ReadResult env = read_source(ctx, "/etc/environment", false);
    if (env.ok) {
        for_each_line(env.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (starts_with(t, "PATH=") && (t.find("/tmp") != std::string::npos || t.find("/dev/shm") != std::string::npos)) {
                Finding f;
                f.rule_id = "LNX.BASE.ENVPATH.001";
                f.severity = "medium";
                f.confidence = "high";
                f.rationale = "/etc/environment PATH 含临时目录: " + t.substr(0, 150);
                f.object_ref = "/etc/environment:" + std::to_string(no);
                f.advice_id = "ADVICE.HARDEN.001";
                ctx.add_finding(f);
            }
        });
        ctx.checked_source("/etc/environment");
    }
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_e"""
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('3. environment PATH done')

# ============ 4. Win 浏览器首页劫持 ============
p = os.path.join(BASE, 'platform', 'win', 'mod_w4.cpp')
s = open(p, encoding='utf-8', newline='').read()
old = "    ctx.set_status(ModuleStatus::PASS);\n}\n\n} // namespace\n\nvoid register_mods_w4"
new = """    // 12) 浏览器首页劫持
    {
        std::string start_page;
        reg_get(HKEY_CURRENT_USER, L"Software\\\\Microsoft\\\\Internet Explorer\\\\Main",
                L"Start Page", false, start_page);
        if (!start_page.empty()) {
            std::string low = to_lower(start_page);
            bool known = contains_ci(low, "bing.com") || contains_ci(low, "google.com") ||
                         contains_ci(low, "baidu.com") || contains_ci(low, "microsoft.com") ||
                         contains_ci(low, "about:blank");
            if (!known) {
                Finding f;
                f.rule_id = "WIN.BASE.BROWSER.001";
                f.severity = "low";
                f.confidence = "medium";
                f.rationale = "浏览器首页被修改为非常见地址: " + start_page.substr(0, 150) + "（暗链/劫持线索）";
                f.object_ref = "IE Start Page";
                f.advice_id = "ADVICE.HOSTS.REVIEW.001";
                ctx.add_finding(f);
            }
        }
        ctx.checked_source("浏览器首页");
    }
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_w4"""
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('4. browser hijack done')

print('\n=== R8 all patches applied ===')
