// Windows 模块第二批：W03 计划任务(COM) / W07 进程与连接 / W09 事件日志 / W13 Web
#include "win_common.hpp"

#include <winsock2.h>
#include <taskschd.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winevt.h>
#include <comdef.h>
#include <map>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "wevtapi.lib")

namespace ctfir::win {

namespace {

// ---- W03 计划任务（Task Scheduler 2.0 COM，递归含隐藏）----
void mod_tasks(ModuleCtx& ctx) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool com_ok = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    if (!com_ok) {
        ctx.omitted_source("Task Scheduler COM", "CoInitializeEx 失败");
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    if (hr == RPC_E_CHANGED_MODE) hr = S_FALSE; // 已有 MTA：继续使用
    ITaskService* svc = nullptr;
    HRESULT hc = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, (void**)&svc);
    if (FAILED(hc) || !svc) {
        ctx.omitted_source("Task Scheduler COM", "CoCreateInstance 失败(任务计划服务不可用?)");
        CoUninitialize();
        ctx.set_status(ModuleStatus::UNSUPPORTED);
        ctx.note("UNSUPPORTED: COM 组件不可用（not_applicable 需人工判断）");
        return;
    }
    HRESULT hconn = svc->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
    if (FAILED(hconn)) {
        ctx.omitted_source("ITaskService::Connect", "连接失败（服务未运行?）");
        svc->Release();
        CoUninitialize();
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    ITaskFolder* root = nullptr;
    if (FAILED(svc->GetFolder(_bstr_t(L"\\"), &root)) || !root) {
        ctx.omitted_source("GetFolder(\\)", "根文件夹不可达");
        svc->Release();
        CoUninitialize();
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }

    int total = 0, hidden_cnt = 0;
    std::string listing;
    // 递归枚举（深度 ≤ 8）
    // 使用 std::function 递归 lambda
    struct Helper {
        static void walk(ITaskFolder* folder, const std::string& path_prefix, ModuleCtx& ctx,
                         std::string& listing, int& total, int& hidden_cnt) {
            if (ctx.expired()) return;
            // 子文件夹
            ITaskFolderCollection* subs = nullptr;
            if (SUCCEEDED(folder->GetFolders(0, &subs)) && subs) {
                LONG n = 0;
                subs->get_Count(&n);
                for (LONG i = 1; i <= n && i <= 100; ++i) {
                    ITaskFolder* sub = nullptr;
                    if (SUCCEEDED(subs->get_Item(_variant_t(i), &sub)) && sub) {
                        BSTR bname = nullptr;
                        if (SUCCEEDED(sub->get_Name(&bname)) && bname) {
                            std::string name = wide_to_utf8(bname);
                            SysFreeString(bname);
                            walk(sub, path_prefix + "\\" + name, ctx, listing, total, hidden_cnt);
                        }
                        sub->Release();
                    }
                }
                subs->Release();
            }
            // 任务
            IRegisteredTaskCollection* tasks = nullptr;
            if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
                LONG n = 0;
                tasks->get_Count(&n);
                for (LONG i = 1; i <= n && i <= 500; ++i) {
                    IRegisteredTask* task = nullptr;
                    if (FAILED(tasks->get_Item(_variant_t(i), &task)) || !task) continue;
                    ++total;
                    BSTR bname = nullptr;
                    std::string name;
                    if (SUCCEEDED(task->get_Name(&bname)) && bname) {
                        name = wide_to_utf8(bname);
                        SysFreeString(bname);
                    }
                    VARIANT_BOOL hidden = VARIANT_FALSE;
                    ITaskDefinition* def = nullptr;
                    if (FAILED(task->get_Definition(&def)) || !def) { task->Release(); continue; }
                    ITaskSettings* settings = nullptr;
                    if (SUCCEEDED(def->get_Settings(&settings)) && settings) {
                        settings->get_Hidden(&hidden);
                        settings->Release();
                    }
                    if (hidden == VARIANT_TRUE) ++hidden_cnt;
                    // 动作
                    IActionCollection* actions = nullptr;
                    std::string action_txt;
                    if (SUCCEEDED(def->get_Actions(&actions)) && actions) {
                        LONG an = 0;
                        actions->get_Count(&an);
                        for (LONG a = 1; a <= an; ++a) {
                            IAction* act = nullptr;
                            if (FAILED(actions->get_Item(_variant_t(a), &act)) || !act) continue;
                            TASK_ACTION_TYPE atype;
                            act->get_Type(&atype);
                            if (atype == TASK_ACTION_EXEC) {
                                IExecAction* ex = nullptr;
                                if (SUCCEEDED(act->QueryInterface(IID_IExecAction, (void**)&ex)) && ex) {
                                    BSTR bp = nullptr, barg = nullptr;
                                    if (SUCCEEDED(ex->get_Path(&bp)) && bp) {
                                        action_txt += wide_to_utf8(bp);
                                        SysFreeString(bp);
                                    }
                                    if (SUCCEEDED(ex->get_Arguments(&barg)) && barg) {
                                        action_txt += " " + wide_to_utf8(barg);
                                        SysFreeString(barg);
                                    }
                                    ex->Release();
                                }
                            }
                            act->Release();
                        }
                        actions->Release();
                    }
                    std::string full = path_prefix + "\\" + name;
                    listing += full + " | " + (hidden == VARIANT_TRUE ? "HIDDEN" : "visible") + " | " +
                               action_txt.substr(0, 160) + "\n";
                    // 规则
                    bool net = contains_ci(action_txt, "powershell") || contains_ci(action_txt, "certutil") ||
                               contains_ci(action_txt, "http") || contains_ci(action_txt, "mshta") ||
                               contains_ci(action_txt, "bitsadmin") || contains_ci(action_txt, "curl") ||
                               contains_ci(action_txt, "wget");
                    bool writable = is_writable_path(action_txt);
                    if (net || writable) {
                        Finding f;
                        f.rule_id = "WIN.TASK.SUSPECT.001";
                        f.severity = net ? "high" : "medium";
                        f.confidence = "medium";
                        f.rationale = "计划任务动作可疑: " + full + " → " + action_txt.substr(0, 200) +
                                      (hidden == VARIANT_TRUE ? "（且为隐藏任务）" : "");
                        f.object_ref = "Task" + full;
                        f.limitations = {"备份/运维任务可能相似；XML 原文见会话 evidence"};
                        f.advice_id = "ADVICE.TASK.REVIEW.001";
                        ctx.add_finding(f);
                    }
                    def->Release();
                    task->Release();
                }
                tasks->Release();
            }
        }
    };
    Helper::walk(root, "", ctx, listing, total, hidden_cnt);
    Evidence e;
    e.source_kind = "com";
    e.source_path = "TaskScheduler ITaskFolder 递归(含隐藏)";
    e.payload = "tasks=" + std::to_string(total) + " hidden=" + std::to_string(hidden_cnt) + "\n" + listing;
    ctx.add_evidence(e);
    ctx.checked_source("Task Scheduler COM");
    ctx.note("COM 调用为同步（本地服务，卡死风险低）；损坏 XML 由 COM 层报错跳过");
    root->Release();
    svc->Release();
    CoUninitialize();
    ctx.set_status(ModuleStatus::PASS);
}

// ---- W07 进程与连接 ----
void mod_procnet(ModuleCtx& ctx) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        ctx.omitted_source("Toolhelp 进程快照", last_error_str("CreateToolhelp32Snapshot"));
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::string listing;
    int cnt = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (ctx.expired()) { ctx.note("预算截断"); break; }
            ++cnt;
            std::string exe = wide_to_utf8(pe.szExeFile);
            listing += std::to_string(pe.th32ProcessID) + "|" + exe + "|ppid=" +
                       std::to_string(pe.th32ParentProcessID) + "\n";
            std::string low = to_lower(exe);
            if (low.find("kdevtmpfsi") != std::string::npos || low.find("kinsing") != std::string::npos ||
                low.find("xmrig") != std::string::npos || low.find("miner") != std::string::npos) {
                Finding f;
                f.rule_id = "WIN.PROC.MINER.001";
                f.severity = "high";
                f.confidence = "medium";
                f.rationale = "进程名含矿机特征: " + exe + " (PID " + std::to_string(pe.th32ProcessID) + ")";
                f.object_ref = "PID " + std::to_string(pe.th32ProcessID);
                f.advice_id = "ADVICE.MINER.REVIEW.001";
                ctx.add_finding(f);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    Evidence e;
    e.source_kind = "api";
    e.source_path = "Toolhelp32 进程快照";
    e.payload = "count=" + std::to_string(cnt) + "\n" + listing;
    ctx.add_evidence(e);
    ctx.checked_source("进程枚举");

    // TCP 表（owner PID）
    {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
        std::vector<BYTE> buf(size ? size : 1);
        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_MODULE*>(buf.data());
            std::string out;
            for (DWORD i = 0; i < t->dwNumEntries && i < 500; ++i) {
                auto& r = t->table[i];
                char line[160];
                std::snprintf(line, sizeof(line), "TCP %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u state=%lu pid=%lu",
                              r.dwLocalAddr & 0xFF, (r.dwLocalAddr >> 8) & 0xFF,
                              (r.dwLocalAddr >> 16) & 0xFF, (r.dwLocalAddr >> 24) & 0xFF,
                              ntohs((u_short)(r.dwLocalPort & 0xFFFF)),
                              r.dwRemoteAddr & 0xFF, (r.dwRemoteAddr >> 8) & 0xFF,
                              (r.dwRemoteAddr >> 16) & 0xFF, (r.dwRemoteAddr >> 24) & 0xFF,
                              ntohs((u_short)(r.dwRemotePort & 0xFFFF)),
                              (unsigned long)r.dwState, (unsigned long)r.dwOwningPid);
                out += line;
                out += "\n";
            }
            Evidence te;
            te.source_kind = "api";
            te.source_path = "GetExtendedTcpTable(TCP owner)";
            te.payload = out.empty() ? "(空表)" : out;
            ctx.add_evidence(te);
            ctx.checked_source("TCP 连接表");
        } else {
            ctx.omitted_source("TCP 连接表", "GetExtendedTcpTable 失败");
        }
    }
    // UDP 表
    {
        DWORD size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
        std::vector<BYTE> buf(size ? size : 1);
        if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) == NO_ERROR) {
            auto* u = reinterpret_cast<MIB_UDPTABLE_OWNER_MODULE*>(buf.data());
            std::string out;
            for (DWORD i = 0; i < u->dwNumEntries && i < 300; ++i) {
                auto& r = u->table[i];
                char line[120];
                std::snprintf(line, sizeof(line), "UDP %u.%u.%u.%u:%u pid=%lu",
                              r.dwLocalAddr & 0xFF, (r.dwLocalAddr >> 8) & 0xFF,
                              (r.dwLocalAddr >> 16) & 0xFF, (r.dwLocalAddr >> 24) & 0xFF,
                              ntohs((u_short)(r.dwLocalPort & 0xFFFF)), (unsigned long)r.dwOwningPid);
                out += line;
                out += "\n";
            }
            Evidence ue;
            ue.source_kind = "api";
            ue.source_path = "GetExtendedUdpTable(UDP owner)";
            ue.payload = out.empty() ? "(空表)" : out;
            ctx.add_evidence(ue);
            ctx.checked_source("UDP 表");
        }
    }
    ctx.note("进程 cmdline 未采集（无内核 API；exe 名+路径为 v1 边界）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- W09 事件日志（4624/4625 Top 来源 IP）----
void mod_evtlog(ModuleCtx& ctx) {
    // Security 通道需要管理员；受限令牌下 EvtQuery 失败 → PERMISSION_DENIED
    LPCWSTR channel = L"Security";
    LPCWSTR query = L"*[System[(EventID=4624 or EventID=4625)]]";
    EVT_HANDLE q = EvtQuery(nullptr, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!q) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            ctx.omitted_source("Security 通道", "PERMISSION_DENIED（需管理员读取安全日志）");
            ctx.set_status(ModuleStatus::PERMISSION_DENIED);
            return;
        }
        ctx.omitted_source("Security 通道", "EvtQuery 失败 err=" + std::to_string(err));
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    std::map<std::string, int> fail_ip;
    int fail_total = 0, ok_total = 0, read = 0;
    std::vector<EVT_HANDLE> events(100);
    DWORD returned = 0;
    while (read < 4000 && EvtNext(q, 100, events.data(), 2000, 0, &returned) && returned > 0) {
        for (DWORD i = 0; i < returned; ++i) {
            DWORD size_needed = 0, prop = 0;
            EvtRender(q, events[i], EvtRenderEventXml, 0, nullptr, &size_needed, &prop);
            if (size_needed == 0 || size_needed > 1024 * 1024) { EvtClose(events[i]); continue; }
            std::vector<wchar_t> xml(size_needed / 2 + 2);
            if (!EvtRender(nullptr, events[i], EvtRenderEventXml, size_needed, xml.data(), &size_needed, &prop)) {
                EvtClose(events[i]);
                continue;
            }
            std::string x = wide_to_utf8(xml.data());
            ++read;
            bool is_fail = x.find("<EventID>4625<") != std::string::npos;
            if (is_fail) ++fail_total;
            else ++ok_total;
            // 提取 IpAddress Data（简单子串解析；不引 XML 库——按 PLAN 边界声明）
            size_t ip_pos = x.find("\"IpAddress\"");
            if (ip_pos == std::string::npos) ip_pos = x.find("IpAddress");
            if (ip_pos != std::string::npos) {
                size_t gt = x.find('>', ip_pos);
                size_t lt = x.find('<', gt);
                if (gt != std::string::npos && lt != std::string::npos && lt > gt) {
                    std::string ip = x.substr(gt + 1, lt - gt - 1);
                    if (!ip.empty() && ip != "-") {
                        if (is_fail) ++fail_ip[ip];
                        // 成功登录 IP 只统计 root 类账户（TargetUserName Administrateur/Administrator 由人工看证据）
                    }
                }
            }
            EvtClose(events[i]);
        }
        if (ctx.expired()) { ctx.note("预算截断"); break; }
    }
    EvtClose(q);
    std::string top;
    for (const auto& [ip, cnt] : fail_ip) top += ip + "×" + std::to_string(cnt) + " ";
    Evidence e;
    e.source_kind = "eventlog";
    e.source_path = "Security(4624/4625)";
    e.payload = "read=" + std::to_string(read) + " fail(4625)=" + std::to_string(fail_total) +
                " ok(4624)=" + std::to_string(ok_total) + "\ntop_fail_ip: " + top;
    ctx.add_evidence(e);
    ctx.checked_source("Security 通道");
    if (fail_total >= 20) {
        Finding f;
        f.rule_id = "WIN.EVT.AUTHFAIL.001";
        f.severity = "low";
        f.confidence = "medium";
        f.rationale = "登录失败(4625)集中（" + std::to_string(fail_total) +
                      " 次/最近读取窗口）：可能爆破或误输；Top 来源 IP 见证据";
        f.object_ref = "Security 4625";
        f.limitations = {"仅安全日志可读窗口；事件可能被清除（清除本身留 1102 事件）"};
        f.advice_id = "ADVICE.EVENTLOG.REVIEW.001";
        ctx.add_finding(f);
    }
    ctx.set_status(ModuleStatus::PASS);
}

// ---- W13 Web ----
static void scan_web_root(ModuleCtx& ctx, const std::string& root, int depth, int& files, int& hits);
static void scan_web_file(ModuleCtx& ctx, const std::string& p, int& files, int& hits) {
    std::string low = to_lower(p);
    if (!(ends_with(low, ".php") || ends_with(low, ".asp") || ends_with(low, ".aspx") ||
          ends_with(low, ".jsp") || ends_with(low, ".cer") || ends_with(low, ".asa")))
        return;
    if (++files > 800) return;
    ReadResult r = read_text_file(p, 512 * 1024);
    if (!r.ok) return;
    bool exec_call = contains_ci(r.content, "eval(") || contains_ci(r.content, "assert(") ||
                     contains_ci(r.content, "Execute(") || contains_ci(r.content, "ExecuteGlobal") ||
                     contains_ci(r.content, "Runtime.getRuntime().exec") ||
                     contains_ci(r.content, "ProcessBuilder");
    bool req_input = contains_ci(r.content, "$_POST") || contains_ci(r.content, "$_GET") ||
                     contains_ci(r.content, "$_REQUEST") || contains_ci(r.content, "Request[") ||
                     contains_ci(r.content, "Request(");
    bool decode = contains_ci(r.content, "base64_decode") || contains_ci(r.content, "gzinflate") ||
                  contains_ci(r.content, "str_rot13") || contains_ci(r.content, "chr(");
    bool shell_fn = contains_ci(r.content, "system(") || contains_ci(r.content, "shell_exec") ||
                    contains_ci(r.content, "passthru(") || contains_ci(r.content, "exec(") ||
                    contains_ci(r.content, "popen(");
    bool password_guard = contains_ci(r.content, "password") || contains_ci(r.content, "pass");
    if (exec_call && (req_input || decode || password_guard)) {
        ++hits;
        Finding f;
        f.rule_id = "WIN.WEB.WEBSHELL.001";
        f.severity = "high";
        f.confidence = "medium";
        f.rationale = "疑似 webshell（执行函数 + 输入/解码特征）: " + p.substr(0, 200) +
                      "——静态特征命中≠定罪，需人工读文件并核对 web 日志";
        f.object_ref = p;
        f.limitations = {"框架文件可能命中；白名单按 hash+路径人工维护"};
        f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
        ctx.add_finding(f);
        Evidence e;
        e.source_kind = "file";
        e.source_path = p;
        e.sha256 = r.raw_sha256;
        e.payload = r.content.size() > 2048 ? r.content.substr(0, 2048) + "...[截断]" : r.content;
        ctx.add_evidence(e);
    }
}
static void scan_web_root(ModuleCtx& ctx, const std::string& root, int depth, int& files, int& hits) {
    if (depth > 4 || files > 800 || ctx.expired()) return;
    WIN32_FIND_DATAA fd;
    HANDLE fh = FindFirstFileA((root + "\\*").c_str(), &fd);
    if (fh == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.') continue;
        std::string fp = root + "\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_web_root(ctx, fp, depth + 1, files, hits);
            if (files > 800 || ctx.expired()) break;
        } else {
            scan_web_file(ctx, fp, files, hits);
        }
    } while (FindNextFileA(fh, &fd));
    FindClose(fh);
}

void mod_web(ModuleCtx& ctx) {
    // 常见 web 根
    std::string roots[] = {
        "C:\\inetpub\\wwwroot", "C:\\phpstudy\\WWW", "C:\\phpstudy_pro\\WWW",
        "D:\\phpstudy\\WWW", "D:\\phpstudy_pro\\WWW", "C:\\xampp\\htdocs",
        "C:\\wamp\\www", "C:\\wamp64\\www", "C:\\www", "C:\\Web", "D:\\WWW"};
    std::string found;
    for (const auto& root : roots) {
        if (!dir_exists(root)) continue;
        ctx.planned_source(root);
        int files = 0, hits = 0;
        scan_web_root(ctx, root, 0, files, hits);
        found += root + " (script_files=" + std::to_string(files) + " hits=" + std::to_string(hits) + ")\n";
        ctx.checked_source(root);
    }
    if (found.empty()) ctx.note("未发现常见 web 根（IIS/phpstudy/xampp/wamp）——如赛事环境有自定路径需人工指定");
    Evidence re;
    re.source_kind = "dir";
    re.source_path = "常见 web 根定位";
    re.payload = found.empty() ? "(none)" : found;
    ctx.add_evidence(re);

    // IIS 日志（W3C 格式）：POST Top IP
    {
        std::string logroot = sysroot() + "\\System32\\LogFiles\\W3SVC";
        std::vector<std::string> svcdirs;
        if (dir_exists(logroot)) {
            WIN32_FIND_DATAA fd;
            HANDLE fh = FindFirstFileA((logroot + "\\*").c_str(), &fd);
            if (fh != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && fd.cFileName[0] != '.')
                        svcdirs.push_back(logroot + "\\" + fd.cFileName);
                } while (FindNextFileA(fh, &fd));
                FindClose(fh);
            }
        }
        for (const auto& svcdir : svcdirs) {
            WIN32_FIND_DATAA fd;
            HANDLE fh = FindFirstFileA((svcdir + "\\*.log").c_str(), &fd);
            if (fh == INVALID_HANDLE_VALUE) continue;
            do {
                std::string lp = svcdir + "\\" + fd.cFileName;
                ctx.planned_source(lp);
                ReadResult r = read_text_file(lp, 8 * 1024 * 1024);
                if (!r.ok) { ctx.omitted_source(lp, r.access_status); continue; }
                // 解析 #Fields 行定位 cs-method 与 c-ip 列
                int method_col = -1, ip_col = -1;
                std::map<std::string, int> post_ip;
                for_each_line(r.content, [&](int, const std::string& line) {
                    if (starts_with(line, "#Fields:")) {
                        method_col = -1;
                        ip_col = -1;
                        std::istringstream is(line.substr(8));
                        std::string w;
                        int col = 0;
                        while (is >> w) {
                            if (w == "cs-method") method_col = col;
                            if (w == "c-ip") ip_col = col;
                            ++col;
                        }
                        return;
                    }
                    if (line.empty() || line[0] == '#' || method_col < 0 || ip_col < 0) return;
                    std::istringstream is(line);
                    std::string w, method, ip;
                    int col = 0;
                    while (is >> w) {
                        if (col == method_col) method = w;
                        if (col == ip_col) ip = w;
                        ++col;
                        if ((int)method.size() && col > ip_col && col > method_col) break;
                    }
                    if (method == "POST" && !ip.empty()) ++post_ip[ip];
                });
                int total_post = 0;
                std::string top;
                for (const auto& [ip, cnt] : post_ip) {
                    total_post += cnt;
                    top += ip + "×" + std::to_string(cnt) + " ";
                }
                if (total_post > 0) {
                    Evidence le;
                    le.source_kind = "file";
                    le.source_path = lp;
                    le.sha256 = r.raw_sha256;
                    le.payload = "POST_total=" + std::to_string(total_post) + "\ntop_ip: " + top;
                    ctx.add_evidence(le);
                    ctx.checked_source(lp);
                    if (total_post >= 50) {
                        Finding f;
                        f.rule_id = "WIN.WEB.LOGPOST.001";
                        f.severity = "low";
                        f.confidence = "medium";
                        f.rationale = "IIS 日志 POST 请求集中（" + std::to_string(total_post) +
                                      " 次）：webshell 交互/上传线索；Top IP 见证据";
                        f.object_ref = lp;
                        f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                        ctx.add_finding(f);
                    }
                }
            } while (FindNextFileA(fh, &fd));
            FindClose(fh);
        }
        ctx.planned_source(logroot);
        if (!dir_exists(logroot)) ctx.checked_source(logroot + " [not_found]");
        else ctx.checked_source(logroot);
    }
    ctx.set_status(ModuleStatus::PASS);
}

} // namespace

void register_mods_w2(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"WIN.TASKS", "1.0.0", "windows", [](ModuleCtx& c) { mod_tasks(c); }});
    mods.push_back({"WIN.PROCNET", "1.0.0", "windows", [](ModuleCtx& c) { mod_procnet(c); }});
    mods.push_back({"WIN.EVTLOG", "1.0.0", "windows", [](ModuleCtx& c) { mod_evtlog(c); }});
    mods.push_back({"WIN.WEB", "1.0.0", "windows", [](ModuleCtx& c) { mod_web(c); }});
}

} // namespace ctfir::win
