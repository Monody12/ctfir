# -*- coding: utf-8 -*-
# v0.5-R9: PowerShell Profile + .lnk target resolution
import os
BASE = r'C:\Users\Administrator\Documents\zcode-projects\ctfir'

# ============ 1. Win PowerShell Profile 检测 ============
p = os.path.join(BASE, 'platform', 'win', 'mod_w4.cpp')
s = open(p, encoding='utf-8', newline='').read()
old = "    ctx.set_status(ModuleStatus::PASS);\n}\n\n} // namespace\n\nvoid register_mods_w4"
new = r'''    // 13) PowerShell Profile 持久化 (T1546.013)
    {
        // $PROFILE 路径（CurrentUserCurrentHost 最常用）
        char up[MAX_PATH]{};
        SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, up);
        std::string doc = std::string(up) + "\\Documents";
        // Win7 SP1+ 默认路径
        std::vector<std::string> profiles = {
            doc + "\\WindowsPowerShell\\profile.ps1",
            doc + "\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
            doc + "\\WindowsPowerShell\\Microsoft.PowerShellISE_profile.ps1",
        };
        // AllUsers 版本
        std::string windir = sysroot();
        profiles.push_back(windir + "\\System32\\WindowsPowerShell\\v1.0\\profile.ps1");
        profiles.push_back(windir + "\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1");

        for (const auto& pf : profiles) {
            ReadResult r = read_text_file(pf, 256 * 1024);
            if (!r.ok) continue;
            // 检查可疑内容
            bool sus = contains_ci(r.content, "invoke-expression") ||
                       contains_ci(r.content, "iex ") ||
                       contains_ci(r.content, "downloadstring") ||
                       contains_ci(r.content, "start-process") ||
                       contains_ci(r.content, "net.webclient") ||
                       contains_ci(r.content, "invoke-webrequest") ||
                       contains_ci(r.content, "certutil") ||
                       contains_ci(r.content, "encodedcommand");
            if (sus) {
                Finding f;
                f.rule_id = "WIN.PERSIST.PSPROFILE.001";
                f.severity = "high";
                f.confidence = "medium";
                f.rationale = "PowerShell Profile 含可疑命令（每次 PS 启动时自动执行）: " + pf.substr(0, 150);
                f.object_ref = pf;
                f.evidence_paths = {pf};
                f.advice_id = "ADVICE.PROFILE.REVIEW.001";
                ctx.add_finding(f);
            }
        }
        ctx.checked_source("PowerShell Profile（5 路径）");
    }

    // 14) Startup .lnk 目标检查 (T1547.009)
    {
        // Startup 文件夹中的 .lnk 文件，解析目标路径（不使用 COM 接口，读二进制找路径）
        for (const char* startup : {NULL}) { break; } // 占位
        char startup_path[MAX_PATH]{};
        if (SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, startup_path) == S_OK) {
            WIN32_FIND_DATAA fd;
            HANDLE fh = FindFirstFileA((std::string(startup_path) + "\\*.lnk").c_str(), &fd);
            if (fh != INVALID_HANDLE_VALUE) {
                do {
                    std::string lnk = std::string(startup_path) + "\\" + fd.cFileName;
                    std::string low = to_lower(lnk);
                    // 读取 .lnk 二进制，提取目标路径（Shell Link Header）
                    ReadResult r = read_text_file(lnk, 64 * 1024);
                    if (!r.ok) continue;
                    // LNK 文件中嵌入 UTF-16 或 ANSI 路径
                    std::string target;
                    size_t pos = r.content.find(":\\");
                    if (pos != std::string::npos && pos >= 1) {
                        // 向前找路径起点
                        size_t start = pos;
                        while (start > 0 && r.content[start - 1] != '\0' && r.content[start - 1] >= 32) start--;
                        // 向后找路径终点
                        size_t end = pos;
                        while (end < r.content.size() && r.content[end] != '\0' && r.content[end] >= 32) end++;
                        target = r.content.substr(start, end - start);
                    }
                    if (!target.empty() && is_writable_path(target)) {
                        Finding f;
                        f.rule_id = "WIN.PERSIST.LNKTARGET.001";
                        f.severity = "medium";
                        f.confidence = "medium";
                        f.rationale = "Startup .lnk 快捷方式指向可写路径: " + lnk + " → " + target.substr(0, 150);
                        f.object_ref = lnk;
                        f.advice_id = "ADVICE.AUTORUN.REVIEW.001";
                        ctx.add_finding(f);
                    }
                } while (FindNextFileA(fh, &fd));
                FindClose(fh);
            }
            ctx.checked_source("Startup .lnk 目标检查");
        }
    }

    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_w4'''
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('1. PSPROFILE + LNK done')

# ============ 2. Linux SSH ProxyCommand + environment PATH ============
p = os.path.join(BASE, 'platform', 'linux', 'mod_a.cpp')
s = open(p, encoding='utf-8', newline='').read()
# SSH ProxyCommand 检查
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

p = os.path.join(BASE, 'platform', 'linux', 'mod_e.cpp')
s = open(p, encoding='utf-8', newline='').read()
old = "    ctx.set_status(ModuleStatus::PASS);\n}\n\n} // namespace\n\nvoid register_mods_e"
new = """    // /etc/environment PATH
    ReadResult env = read_source(ctx, "/etc/environment", false);
    if (env.ok) {
        for_each_line(env.content, [&](int no, const std::string& line) {
            std::string t = trim(line);
            if (starts_with(t, "PATH=") &&
                (t.find("/tmp") != std::string::npos || t.find("/dev/shm") != std::string::npos)) {
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

print('\n=== R9 all patches applied ===')
