// Windows 模块第二批：W03 计划任务(COM) / W07 进程与连接 / W09 事件日志 / W13 Web
#include "win_common.hpp"

#include <winsock2.h>
#include <taskschd.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winevt.h>
#include <wbemidl.h>
#include <comdef.h>
#include <map>
#include <set>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace ctfir::win {

namespace {

// XML Data 字段提取（Name="X">value< ——只做子串定位，不引 XML 库，见 PLAN 边界声明）
static std::string xml_data(const std::string& x, const char* name) {
    std::string pat = std::string("Name=\"") + name + "\">";
    size_t p = x.find(pat);
    if (p == std::string::npos) return "";
    size_t s = p + pat.size(), e = x.find('<', s);
    return (e == std::string::npos) ? "" : x.substr(s, e - s);
}

// SystemTime 属性 → 规整为 YYYY-MM-DDTHH:MM:SSZ（去毫秒，供 beijing_time_str 解析）
static std::string xml_time(const std::string& x) {
    size_t p = x.find("SystemTime=\"");
    if (p == std::string::npos) return "";
    size_t s = p + 12, e = x.find('"', s);
    std::string t = (e == std::string::npos) ? "" : x.substr(s, e - s);
    if (t.size() >= 19) t = t.substr(0, 19) + "Z";
    return t;
}

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
                    // 状态（A7C9-W04 事实化：禁用任务要呈现"不会执行"）
                    TASK_STATE tstate = TASK_STATE_UNKNOWN;
                    task->get_State(&tstate);
                    std::string state =
                        tstate == TASK_STATE_DISABLED ? "Disabled" :
                        tstate == TASK_STATE_QUEUED ? "Queued" :
                        tstate == TASK_STATE_READY ? "Ready" :
                        tstate == TASK_STATE_RUNNING ? "Running" : "Unknown";
                    VARIANT_BOOL hidden = VARIANT_FALSE;
                    ITaskDefinition* def = nullptr;
                    if (FAILED(task->get_Definition(&def)) || !def) { task->Release(); continue; }
                    ITaskSettings* settings = nullptr;
                    if (SUCCEEDED(def->get_Settings(&settings)) && settings) {
                        settings->get_Hidden(&hidden);
                        settings->Release();
                    }
                    if (hidden == VARIANT_TRUE) ++hidden_cnt;
                    // 首触发器时间
                    std::string trig_txt;
                    {
                        ITriggerCollection* trigs = nullptr;
                        if (SUCCEEDED(def->get_Triggers(&trigs)) && trigs) {
                            LONG tn = 0;
                            trigs->get_Count(&tn);
                            for (LONG k = 1; k <= tn && k <= 5; ++k) {
                                ITrigger* tg = nullptr;
                                if (SUCCEEDED(trigs->get_Item(_variant_t(k), &tg)) && tg) {
                                    BSTR bs = nullptr;
                                    VARIANT_BOOL ten = VARIANT_TRUE;
                                    tg->get_Enabled(&ten);
                                    if (SUCCEEDED(tg->get_StartBoundary(&bs)) && bs) {
                                        trig_txt += std::string(ten == VARIANT_TRUE ? "" : "[disabled]") +
                                                    wide_to_utf8(bs) + " ";
                                        SysFreeString(bs);
                                    }
                                    tg->Release();
                                }
                            }
                            trigs->Release();
                        }
                    }
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
                    listing += full + " | " + state + " | " +
                               (hidden == VARIANT_TRUE ? "HIDDEN" : "visible") + " | " +
                               action_txt.substr(0, 160) + "\n";
                    // 事实化（A7C9-W04）：非系统任务逐条呈现，禁用任务标注"不会执行"
                    if (full.find("\\Microsoft\\") != 0) {
                        Finding f;
                        f.rule_id = "WIN.TASK.FACT.001";
                        f.severity = "low";
                        f.confidence = "high";
                        f.rationale = "非系统计划任务: " + full +
                                      "（状态 " + state +
                                      (tstate == TASK_STATE_DISABLED ? "，禁用中不会执行" : "") +
                                      "；触发器: " + (trig_txt.empty() ? "无/手动" : trig_txt.substr(0, 80)) +
                                      "）——事实呈现，需按动作内容判断性质";
                        f.object_ref = "Task" + full;
                        f.limitations = {"备份/运维任务属正常；禁用≠无害"};
                        f.advice_id = "ADVICE.TASK.REVIEW.001";
                        ctx.add_finding(f);
                    }
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
                    } else if (full.find("\\Microsoft\\") != 0) {
                        // 引用路径分析（A7C9-W03 同构）：动作引用非常规路径——仅非系统任务
                        for (const auto& rp : extract_paths(action_txt)) {
                            if (is_expected_path(rp)) continue;
                            Finding f;
                            f.rule_id = "WIN.TASK.REFPATH.001";
                            f.severity = "medium";
                            f.confidence = "medium";
                            f.rationale = "计划任务引用非常规路径: " + full + " → " + rp.substr(0, 150);
                            f.object_ref = "Task" + full;
                            f.advice_id = "ADVICE.TASK.REVIEW.001";
                            ctx.add_finding(f);
                            break;
                        }
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

// ---- W09 事件日志（4624/4625 登录 + 4720-4732 账户生命周期时间线）----
void mod_evtlog(ModuleCtx& ctx) {
    // Security 通道需要管理员；受限令牌下 EvtQuery 失败 → PERMISSION_DENIED
    LPCWSTR channel = L"Security";
    LPCWSTR query = L"*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4722 "
                    L"or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4732 or EventID=1102)]]";
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
    std::vector<std::string> created;      // 4720 新建账户（逐条 medium）
    std::vector<std::string> mgmt_timeline;
    bool log_cleared = false; // 4722/4724/4725/4726/4732 聚合
    std::vector<EVT_HANDLE> events(100);
    DWORD returned = 0;
    while (read < 4000 && EvtNext(q, 100, events.data(), 2000, 0, &returned) && returned > 0) {
        for (DWORD i = 0; i < returned; ++i) {
            DWORD size_needed = 0, prop = 0;
            EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &size_needed, &prop);
            if (size_needed == 0 || size_needed > 1024 * 1024) { EvtClose(events[i]); continue; }
            std::vector<wchar_t> xml(size_needed / 2 + 2);
            if (!EvtRender(nullptr, events[i], EvtRenderEventXml, size_needed, xml.data(), &size_needed, &prop)) {
                EvtClose(events[i]);
                continue;
            }
            std::string x = wide_to_utf8(xml.data());
            ++read;
            int eid = 0;
            {
                size_t p1 = x.find("<EventID>");
                if (p1 != std::string::npos) eid = std::atoi(x.c_str() + p1 + 9);
            }
            std::string t = xml_time(x);
            std::string tb = t.empty() ? "" : beijing_time_str(t);
            std::string target = xml_data(x, "TargetUserName");
            std::string ip = xml_data(x, "IpAddress");
            std::string member = xml_data(x, "MemberName");
            std::string group = xml_data(x, "TargetUserName");
            if (eid == 0) { size_t p1 = x.find("<EventID>"); if (p1 != std::string::npos) eid = std::atoi(x.c_str() + p1 + 9); }

            if (eid == 4625) {
                ++fail_total;
                if (!ip.empty() && ip != "-") ++fail_ip[ip];
            } else if (eid == 4624) {
                ++ok_total;
            } else if (eid == 4720) {
                created.push_back(tb + " 创建账户 " + target);
            } else if (eid == 4722) {
                mgmt_timeline.push_back(tb + " 启用账户 " + target);
            } else if (eid == 4724) {
                mgmt_timeline.push_back(tb + " 重置密码 " + target);
            } else if (eid == 4725) {
                mgmt_timeline.push_back(tb + " 禁用账户 " + target);
            } else if (eid == 4726) {
                mgmt_timeline.push_back(tb + " 删除账户 " + target);
            } else if (eid == 4732) {
                mgmt_timeline.push_back(tb + " 加入组 " + (member.empty() ? "?" : member) + " → " + group);
            } else if (eid == 1102) {
                log_cleared = true;
                mgmt_timeline.push_back(tb + " 安全日志被清除！");
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
    e.source_path = "Security(4624/4625/4720-4732)";
    e.payload = "read=" + std::to_string(read) + " fail(4625)=" + std::to_string(fail_total) +
                " ok(4624)=" + std::to_string(ok_total) +
                " account_created(4720)=" + std::to_string(created.size()) +
                " log_cleared(1102)=" + std::string(log_cleared ? "YES" : "no") +
                "\ntop_fail_ip: " + top +
                (mgmt_timeline.empty() ? "" : "\n--- 账户管理事件 ---\n" + join(mgmt_timeline, "\n"));
    ctx.add_evidence(e);
    ctx.checked_source("Security 通道");
    // 4720 逐条：CTF 直答"后门账户何时创建"
    for (const auto& c : created) {
        Finding f;
        f.rule_id = "WIN.EVT.ACC.CREATE.001";
        f.severity = "medium";
        f.confidence = "high";
        f.rationale = "安全日志记录到新建本地账户: " + c + "（北京时间）——结合授权运维记录核实";
        f.object_ref = "Security 4720";
        f.limitations = {"日志可能被清除（1102 事件）；时间取自事件本地记录"};
        f.advice_id = "ADVICE.ACC.REVIEW.001";
        ctx.add_finding(f);
    }
    if (!mgmt_timeline.empty()) {
        Finding f;
        f.rule_id = "WIN.EVT.ACC.TIMELINE.001";
        f.severity = "low";
        f.confidence = "high";
        f.rationale = "账户管理事件时间线（启用/重置/禁用/删除/入组，共 " +
                      std::to_string(mgmt_timeline.size()) + " 条）——详见证据；加入管理员组(4732)重点关注";
        f.object_ref = "Security 4722-4732";
        f.advice_id = "ADVICE.EVENTLOG.REVIEW.001";
        ctx.add_finding(f);
    }
    if (log_cleared) {
        Finding f;
        f.rule_id = "WIN.EVT.LOGCLEAR.001";
        f.severity = "high";
        f.confidence = "high";
        f.rationale = "安全日志被清除（Event 1102）——攻击者痕迹擦除的强指标";
        f.object_ref = "Security 1102";
        f.advice_id = "ADVICE.EVENTLOG.REVIEW.001";
        ctx.add_finding(f);
    }
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

// ---- WIN.PROCCMD：WMI 进程命令行（cmdline 规则落地 + 端口关联）----
void mod_proccmd(ModuleCtx& ctx) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        ctx.omitted_source("WMI", "CoInitializeEx 失败");
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    // 进程级一次；若已被设置会报 TOO_LATE——忽略继续（默认安全级可用）
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    IWbemLocator* loc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator, (void**)&loc)) || !loc) {
        ctx.omitted_source("WMI 定位器", "CoCreateInstance 失败");
        ctx.set_status(ModuleStatus::UNSUPPORTED);
        return;
    }
    IWbemServices* svc = nullptr;
    if (FAILED(loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr,
                                  0, nullptr, nullptr, &svc)) || !svc) {
        ctx.omitted_source("WMI ConnectServer", "失败（服务未运行?）");
        loc->Release();
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    IEnumWbemClassObject* en = nullptr;
    if (FAILED(svc->ExecQuery(_bstr_t(L"WQL"),
                              _bstr_t(L"SELECT ProcessId, Name, CommandLine FROM Win32_Process"),
                              WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                              nullptr, &en)) || !en) {
        ctx.omitted_source("WMI ExecQuery", "失败");
        svc->Release(); loc->Release();
        ctx.set_status(ModuleStatus::ERROR);
        return;
    }
    std::map<DWORD, std::string> cmd_by_pid;
    std::string listing;
    int cnt = 0;
    for (;;) {
        IWbemClassObject* obj = nullptr;
        ULONG got = 0;
        if (en->Next(WBEM_INFINITE, 1, &obj, &got) != WBEM_S_NO_ERROR || got == 0) break;
        VARIANT vp, vn, vc;
        VariantInit(&vp); VariantInit(&vn); VariantInit(&vc);
        bool ok_pid = SUCCEEDED(obj->Get(L"ProcessId", 0, &vp, nullptr, nullptr)) && vp.vt == VT_I4;
        bool ok_name = SUCCEEDED(obj->Get(L"Name", 0, &vn, nullptr, nullptr)) && vn.vt == VT_BSTR;
        bool ok_cmd = SUCCEEDED(obj->Get(L"CommandLine", 0, &vc, nullptr, nullptr)) && vc.vt == VT_BSTR;
        if (ok_pid) {
            DWORD pid = static_cast<DWORD>(vp.lVal);
            std::string name = ok_name ? wide_to_utf8(vn.bstrVal) : "";
            std::string cl = ok_cmd ? wide_to_utf8(vc.bstrVal) : "";
            if (!cl.empty()) {
                ++cnt;
                cmd_by_pid[pid] = cl;
                listing += std::to_string(pid) + "|" + name + "|" + cl.substr(0, 200) + "\n";
                bool miner = contains_ci(cl, "stratum") || contains_ci(cl, "xmrig") ||
                             contains_ci(cl, "kdevtmpfsi") || contains_ci(cl, "kinsing");
                bool stealth = contains_ci(cl, "-enc ") || contains_ci(cl, "-w hidden") ||
                               contains_ci(cl, "-nop -w") || contains_ci(cl, "frombase64string") ||
                               (contains_ci(cl, "certutil") && contains_ci(cl, "urlcache")) ||
                               contains_ci(cl, "bitsadmin /transfer");
                if (miner || stealth) {
                    Finding f;
                    f.rule_id = "WIN.PROC.CMDLINE.001";
                    f.severity = "high";
                    f.confidence = "medium";
                    f.rationale = std::string("进程命令行") + (miner ? "含矿池/矿机特征" : "含隐藏执行/下载特征") +
                                  ": PID " + std::to_string(pid) + " " + cl.substr(0, 220);
                    f.object_ref = "PID " + std::to_string(pid);
                    f.advice_id = "ADVICE.MINER.REVIEW.001";
                    ctx.add_finding(f);
                }
            }
        }
        VariantClear(&vp); VariantClear(&vn); VariantClear(&vc);
        obj->Release();
        if (ctx.expired()) { ctx.note("预算截断"); break; }
    }
    en->Release(); svc->Release(); loc->Release();
    // 端口关联（TCP owner 表复用）
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
    std::vector<BYTE> tb(sz ? sz : 1);
    std::map<DWORD, std::string> ports_by_pid;
    if (GetExtendedTcpTable(tb.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) == NO_ERROR) {
        auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_MODULE*>(tb.data());
        for (DWORD i = 0; i < t->dwNumEntries && i < 500; ++i) {
            auto& r = t->table[i];
            char b[32];
            std::snprintf(b, sizeof(b), "%u", ntohs((u_short)(r.dwRemotePort & 0xFFFF)));
            std::string local;
            std::snprintf(b, sizeof(b), "%u", ntohs((u_short)(r.dwLocalPort & 0xFFFF)));
            local = b;
            ports_by_pid[r.dwOwningPid] += local + " ";
        }
    }
    std::string assoc;
    for (const auto& [pid, ports] : ports_by_pid) {
        auto it = cmd_by_pid.find(pid);
        if (it != cmd_by_pid.end() && !ports.empty())
            assoc += "PID " + std::to_string(pid) + " 本地端口[" + ports + "] " + it->second.substr(0, 120) + "\n";
    }
    Evidence e;
    e.source_kind = "wmi";
    e.source_path = "Win32_Process(CommandLine) + TCP owner 关联";
    e.payload = "with_cmdline=" + std::to_string(cnt) + "\n" + listing +
                (assoc.empty() ? "" : "--- 端口关联 ---\n" + assoc);
    ctx.add_evidence(e);
    ctx.checked_source("WMI Win32_Process");
    ctx.note("cmdline 经 WMI 只读采集；服务进程命令行可能为空");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.FILES：用户目录巡检（双扩展名/临时目录可执行/基线比对）----
static bool looks_exec_name(const std::string& low) {
    return ends_with(low, ".exe") || ends_with(low, ".scr") || ends_with(low, ".com") ||
           ends_with(low, ".bat") || ends_with(low, ".cmd") || ends_with(low, ".js") ||
           ends_with(low, ".vbs") || ends_with(low, ".ps1") || ends_with(low, ".jar");
}

void mod_files(ModuleCtx& ctx) {
    // 目录集
    std::vector<std::string> dirs;
    char tmp[MAX_PATH]{};
    if (GetTempPathA(MAX_PATH, tmp)) dirs.push_back(std::string(tmp));
    char up[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, up))) {
        std::string u = up;
        dirs.push_back(u + "\\Downloads");
        dirs.push_back(u + "\\Desktop");
    }
    dirs.push_back("C:\\Users\\Public");
    for (const auto& d : ctx.config().extra_dirs) dirs.push_back(d);
    // 基线装载（"路径 sha256" 或 "sha256 路径" 双序兼容；64 hex 识别）
    std::map<std::string, std::string> baseline; // lower(path) → sha256
    if (!ctx.config().baseline_path.empty()) {
        ctx.planned_source(ctx.config().baseline_path);
        ReadResult br = read_text_file(ctx.config().baseline_path, 4 * 1024 * 1024);
        if (br.ok) {
            for_each_line(br.content, [&](int, const std::string& line) {
                std::istringstream is(line);
                std::string path, sha;
                std::string tok;
                while (is >> tok) {
                    if (tok.size() == 64) {
                        bool hexish = true;
                        for (char c : tok)
                            if (!std::isxdigit(static_cast<unsigned char>(c))) { hexish = false; break; }
                        if (hexish) { sha = to_lower(tok); continue; }
                    }
                    if (path.empty()) path = tok;
                }
                if (!path.empty() && sha.size() == 64) {
                    std::string lp = to_lower(path);
                    baseline[lp] = sha;
                    // 相对路径兜底：再登记 basename 键
                    size_t bs = lp.find_last_of("\\/");
                    if (bs != std::string::npos) baseline[lp.substr(bs + 1)] = sha;
                }
            });
            ctx.checked_source("基线清单 " + std::to_string(baseline.size()) + " 条");
        } else {
            ctx.omitted_source(ctx.config().baseline_path, br.access_status);
        }
    }
    int files = 0;
    int double_ext = 0, tempexe = 0, mismatch = 0;
    std::set<std::string> baseline_seen;
    // 简单深度受限遍历
    struct Walker {
        static void walk(ModuleCtx& ctx, const std::string& dir, int depth, int& files,
                         int& double_ext, int& tempexe, int& mismatch,
                         std::map<std::string, std::string>& baseline,
                         std::set<std::string>& baseline_seen) {
            if (depth > 3 || files > 800 || ctx.expired()) return;
            WIN32_FIND_DATAA fd;
            HANDLE fh = FindFirstFileA((dir + "\\*").c_str(), &fd);
            if (fh == INVALID_HANDLE_VALUE) return;
            do {
                if (fd.cFileName[0] == '.') continue;
                std::string fp = dir + "\\" + fd.cFileName;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    walk(ctx, fp, depth + 1, files, double_ext, tempexe, mismatch, baseline, baseline_seen);
                    if (files > 800 || ctx.expired()) break;
                    continue;
                }
                if (++files > 800) break;
                std::string low = to_lower(fp);
                std::string namelow = to_lower(fd.cFileName);
                // 双扩展名（invoice.pdf.exe 类；排除合法归档与版本号 .3-1 等伪扩展）
                if (namelow.find('.', 1) != std::string::npos) {
                    size_t last = namelow.rfind('.');
                    std::string lastext = namelow.substr(last);
                    std::string before = namelow.substr(0, last);
                    size_t prev = before.rfind('.');
                    std::string prevext = prev == std::string::npos ? "" : before.substr(prev);
                    bool prev_archive = prevext == ".zip" || prevext == ".rar" || prevext == ".7z" ||
                                        prevext == ".tar" || prevext == ".gz" || prevext == ".bz2" ||
                                        prevext == ".xz" || prevext == ".tgz";
                    // 伪扩展校验：须为 [字母][字母数字]{1,4}，纯数字/含 - 的版本号不算
                    bool prev_real_ext = prevext.size() >= 2 && prevext[0] == '.';
                    if (prev_real_ext) {
                        bool has_alpha = false;
                        for (size_t k = 1; k < prevext.size(); ++k) {
                            char c = prevext[k];
                            if (c == '-' || c == '_') { prev_real_ext = false; break; }
                            if (std::isalpha(static_cast<unsigned char>(c))) has_alpha = true;
                            else if (!std::isalnum(static_cast<unsigned char>(c))) { prev_real_ext = false; break; }
                        }
                        if (!has_alpha) prev_real_ext = false;
                    }
                    if (looks_exec_name(namelow) && !prev_archive && prev_real_ext) {
                        ++double_ext;
                        Finding f;
                        f.rule_id = "WIN.FILES.DOUBLEEXT.001";
                        f.severity = "medium";
                        f.confidence = "medium";
                        f.rationale = "疑似双扩展名伪装（" + prevext + " → " + lastext +
                                      "）: " + fp + "——仅为伪装线索，需人工查看内容，不判定木马";
                        f.object_ref = fp;
                        f.advice_id = "ADVICE.WEBSHELL.REVIEW.001";
                        ctx.add_finding(f);
                    }
                }
                // 临时目录可执行
                if (looks_exec_name(namelow) && is_writable_path(fp)) {
                    ++tempexe;
                    Finding f;
                    f.rule_id = "WIN.FILES.TEMPEXE.001";
                    f.severity = "medium";
                    f.confidence = "medium";
                    f.rationale = "可执行文件位于临时/可写目录: " + fp.substr(0, 180);
                    f.object_ref = fp;
                    f.advice_id = "ADVICE.MINER.REVIEW.001";
                    ctx.add_finding(f);
                }
                // 最近 7 天修改的可执行/脚本（新投毒线索；mtime 线索级 low）
                if (looks_exec_name(namelow)) {
                    SYSTEMTIME st;
                    FILETIME now_ft;
                    GetSystemTime(&st);
                    SystemTimeToFileTime(&st, &now_ft);
                    ULARGE_INTEGER cur;
                    cur.LowPart = now_ft.dwLowDateTime;
                    cur.HighPart = now_ft.dwHighDateTime;
                    ULARGE_INTEGER wr;
                    wr.LowPart = fd.ftLastWriteTime.dwLowDateTime;
                    wr.HighPart = fd.ftLastWriteTime.dwHighDateTime;
                    // FILETIME 100ns 单位：7 天 = 7 × 86400 × 10,000,000
                    if (cur.QuadPart > wr.QuadPart &&
                        (cur.QuadPart - wr.QuadPart) < 7ULL * 86400 * 10000000ULL) {
                        SYSTEMTIME lst;
                        FileTimeToSystemTime(&fd.ftLastWriteTime, &lst);
                        char tbuf[24];
                        snprintf(tbuf, sizeof(tbuf), "%04d-%02d-%02d %02d:%02d",
                                 lst.wYear, lst.wMonth, lst.wDay, lst.wHour, lst.wMinute);
                        Finding f;
                        f.rule_id = "WIN.FILES.RECENT.001";
                        f.severity = "low";
                        f.confidence = "low";
                        f.rationale = "最近 7 天内修改的可执行/脚本文件: " + fp.substr(0, 180) +
                                      "（mtime " + tbuf + "）——新投毒线索";
                        f.object_ref = fp;
                        f.advice_id = "ADVICE.HASH.BASELINE.001";
                        ctx.add_finding(f);
                    }
                }
                // 基线比对（W06）
                if (!baseline.empty()) {
                    auto it = baseline.find(low);
                    if (it == baseline.end()) {
                        std::string bn = low.substr(low.find_last_of("\\/") + 1);
                        it = baseline.find(bn);
                    }
                    if (it != baseline.end()) {
                        baseline_seen.insert(low);
                        ReadResult r = read_text_file(fp, 8 * 1024 * 1024);
                        if (r.ok && r.raw_sha256 != it->second) {
                            ++mismatch;
                            Finding f;
                            f.rule_id = "WIN.FILES.BASELINE.001";
                            f.severity = "medium";
                            f.confidence = "high";
                            f.rationale = "基线哈希不一致: " + fp +
                                          "（基线 " + it->second.substr(0, 16) + "… / 当前 " +
                                          r.raw_sha256.substr(0, 16) + "…）——仅对清单内文件判定；无合理解释（编辑/换行转换）需人工核实";
                            f.object_ref = fp;
                            f.advice_id = "ADVICE.HASH.BASELINE.001";
                            ctx.add_finding(f);
                        }
                    }
                }
            } while (FindNextFileA(fh, &fd));
            FindClose(fh);
        }
    };
    for (const auto& d : dirs) {
        if (!dir_exists(d)) continue;
        ctx.planned_source(d);
        Walker::walk(ctx, d, 0, files, double_ext, tempexe, mismatch, baseline, baseline_seen);
        ctx.checked_source(d);
    }
    // 基线内缺失文件
    for (const auto& [low, sha] : baseline) {
        if (baseline_seen.count(low)) continue;
        Finding f;
        f.rule_id = "WIN.FILES.BASELINE.MISS.001";
        f.severity = "low";
        f.confidence = "medium";
        f.rationale = "基线清单中的文件未找到: " + low + "（被删除/移动？——W06 类考点常见形态）";
        f.object_ref = low;
        f.advice_id = "ADVICE.HASH.BASELINE.001";
        ctx.add_finding(f);
    }
    Evidence e;
    e.source_kind = "dir";
    e.source_path = "用户目录巡检";
    e.payload = "files=" + std::to_string(files) + " double_ext=" + std::to_string(double_ext) +
                " temp_exec=" + std::to_string(tempexe) + " baseline_mismatch=" + std::to_string(mismatch) +
                " baseline_total=" + std::to_string(baseline.size());
    ctx.add_evidence(e);
    ctx.note("巡检有预算与文件数上限（800）；不读文件内容仅哈希（双扩展名文件不执行）");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.RANSOM：勒索软件痕迹（勒索信文件名 + 加密扩展名 + 壁纸篡改）----
void mod_ransom(ModuleCtx& ctx) {
    static const char* note_kws[] = {
        "readme", "decrypt", "ransom", "restore_files", "recover", "how_to_decrypt",
        "help_decrypt", "your_files", "read_me",
    };
    static const char* enc_exts[] = {
        ".locked", ".encrypted", ".crypt", ".wcry", ".onion", ".cerber",
        ".locky", ".crypto", ".enciphered", ".paymen", ".poisoned", ".crypted",
    };
    std::vector<std::string> dirs;
    char up[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, up))) {
        std::string u = up;
        dirs.push_back(u + "\\Desktop");
        dirs.push_back(u + "\\Documents");
        dirs.push_back(u + "\\Downloads");
    }
    dirs.push_back("C:\\Users\\Public");
    int hits = 0;
    for (const auto& d : dirs) {
        WIN32_FIND_DATAA fd;
        HANDLE fh = FindFirstFileA((d + "\\*").c_str(), &fd);
        if (fh == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.cFileName[0] == '.') continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::string base = to_lower(fd.cFileName);
            bool is_note = false;
            for (const char* kw : note_kws)
                if (base.find(kw) != std::string::npos &&
                    (ends_with(base, ".txt") || ends_with(base, ".html") ||
                     ends_with(base, ".hta"))) { is_note = true; break; }
            bool is_enc = false;
            for (const char* ext : enc_exts) {
                std::string e(ext);
                if (!e.empty() && ends_with(base, e)) { is_enc = true; break; }
            }
            if (!is_note && !is_enc) continue;
            if (base.find("ctfir") != std::string::npos) continue;
            ++hits;
            if (hits <= 10) {
                Finding f;
                f.rule_id = "WIN.RANSOM.TRACE.001";
                f.severity = "high";
                f.confidence = "low";
                f.rationale = std::string("勒索软件痕迹（") + (is_note ? "勒索信" : "加密扩展名") +
                              "）: " + d + "\\" + fd.cFileName + "——需人工核实内容";
                f.object_ref = d + "\\" + fd.cFileName;
                f.advice_id = "ADVICE.HASH.BASELINE.001";
                ctx.add_finding(f);
            }
        } while (FindNextFileA(fh, &fd));
        FindClose(fh);
    }
    // 壁纸篡改（勒索软件常用：桌面壁纸指向临时/可疑路径或被换成勒索图）
    {
        std::string wp;
        reg_get(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"Wallpaper", false, wp);
        // 白名单：Windows 自身壁纸缓存/主题路径（TranscodedWallpaper 等属正常）
        std::string wpl = to_lower(wp);
        bool wp_normal = wpl.find("\\themes\\") != std::string::npos ||
                         wpl.find("\\appdata\\") != std::string::npos ||
                         wpl.find("\\windows\\web\\") != std::string::npos;
        if (!wp.empty() && !wp_normal && is_writable_path(wp) && !is_expected_path(wp)) {
            Finding f;
            f.rule_id = "WIN.RANSOM.WALLPAPER.001";
            f.severity = "medium";
            f.confidence = "low";
            f.rationale = "桌面壁纸指向非常规路径: " + wp.substr(0, 150) +
                          "（勒索软件/篡改痕迹线索，需人工看图）";
            f.object_ref = "HKCU\\Control Panel\\Desktop\\Wallpaper";
            f.advice_id = "ADVICE.HOSTS.REVIEW.001";
            ctx.add_finding(f);
        }
    }
    ctx.note("勒索痕迹扫描：勒索信文件名 + 加密扩展名 + 壁纸篡改；置信度 low 需人工核实");
    ctx.set_status(ModuleStatus::PASS);
}

// ---- WIN.AUDITPOL：审核策略状态（auditpol 只读收集；等保"日志审计"前提）----
void mod_auditpol(ModuleCtx& ctx) {
    // auditpol 输出重定向到临时文件再读取（避免引入管道语义）
    char tmp[MAX_PATH]{};
    GetTempPathA(MAX_PATH, tmp);
    std::string out_file = std::string(tmp) + "ctfir_auditpol.txt";
    std::string cmd = "auditpol /get /category:* /r > \"" + out_file + "\" 2>nul";
    int rc = std::system(cmd.c_str());
    ctx.planned_source("auditpol /get /category:*");
    if (rc != 0) {
        ctx.omitted_source("auditpol", "command_failed");
        DeleteFileA(out_file.c_str());
        ctx.note("auditpol 执行失败（需管理员权限）——审核策略需人工核对");
        ctx.set_status(ModuleStatus::PASS);
        return;
    }
    ReadResult r = read_text_file(out_file, 256 * 1024);
    DeleteFileA(out_file.c_str());
    if (!r.ok) {
        ctx.omitted_source(out_file, "not_found");
        ctx.set_status(ModuleStatus::PASS);
        return;
    }
    // CSV 行：Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
    int audited = 0, disabled = 0;
    std::vector<std::string> disabled_high; // 高价值子类被关
    for_each_line(r.content, [&](int, const std::string& line) {
        if (line.find(',') == std::string::npos) return;
        // 取第 3 列（子类）和第 5 列（包含设置）
        int col = 0;
        size_t p1 = 0, p2 = 0;
        std::string sub, inc;
        for (size_t i = 0; i <= line.size(); ++i) {
            if (i == line.size() || line[i] == ',') {
                ++col;
                std::string cell = line.substr(p1, i - p1);
                if (col == 3) sub = cell;
                if (col == 5) { inc = cell; break; }
                p1 = i + 1;
            }
        }
        if (sub.empty() || inc.empty()) return;
        ++audited;
        if (contains_ci(inc, "no auditing")) {
            ++disabled;
            if (disabled_high.size() < 8 &&
                (contains_ci(sub, "logon") || contains_ci(sub, "process creation") ||
                 contains_ci(sub, "account") || contains_ci(sub, "other logon")))
                disabled_high.push_back(sub);
        }
    });
    Evidence e;
    e.source_kind = "command";
    e.source_path = "auditpol /get /category:*";
    e.payload = "subcategories=" + std::to_string(audited) + " no_auditing=" + std::to_string(disabled);
    ctx.add_evidence(e);
    if (disabled > 0 && !disabled_high.empty()) {
        Finding f;
        f.rule_id = "WIN.AUDIT.DISABLED.001";
        f.severity = "medium";
        f.confidence = "high";
        f.rationale = "关键审核子类未开启（No Auditing）: " + join(disabled_high, "、") +
                      "——相关事件日志将缺失，入侵研判证据盲区（等保基线项）";
        f.object_ref = "auditpol";
        f.advice_id = "ADVICE.HARDEN.001";
        ctx.add_finding(f);
    }
    ctx.checked_source("审核策略（auditpol " + std::to_string(audited) + " 子类）");
    ctx.set_status(ModuleStatus::PASS);
}

void register_mods_w2(std::vector<Session::ModuleDef>& mods) {
    mods.push_back({"WIN.TASKS", "1.0.0", "windows", [](ModuleCtx& c) { mod_tasks(c); }});
    mods.push_back({"WIN.PROCNET", "1.0.0", "windows", [](ModuleCtx& c) { mod_procnet(c); }});
    mods.push_back({"WIN.EVTLOG", "1.0.0", "windows", [](ModuleCtx& c) { mod_evtlog(c); }});
    mods.push_back({"WIN.WEB", "1.0.0", "windows", [](ModuleCtx& c) { mod_web(c); }});
    mods.push_back({"WIN.PROCCMD", "1.0.0", "windows", [](ModuleCtx& c) { mod_proccmd(c); }});
    mods.push_back({"WIN.FILES", "1.0.0", "windows", [](ModuleCtx& c) { mod_files(c); }});
    mods.push_back({"WIN.RANSOM", "1.0.0", "windows", [](ModuleCtx& c) { mod_ransom(c); }});
    mods.push_back({"WIN.AUDITPOL", "1.0.0", "windows", [](ModuleCtx& c) { mod_auditpol(c); }});
}

} // namespace ctfir::win
