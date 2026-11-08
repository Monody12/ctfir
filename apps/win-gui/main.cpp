// ctfir-gui — Win32 原生只读应急扫描 GUI（WP5）
// 纪律：扫描在后台线程；UI 只读展示；无任何"修复/执行"入口；双击不运行证据。
// --selftest --out <file>：建窗泵消息 1.5s 自退（无人值守冒烟）。
#include "core/session.hpp"
#include "core/report.hpp"
#include "core/advice.hpp"
#include "core/util.hpp"
#include "platform/modules_registry.hpp"

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <thread>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// windows.h 的 ERROR 宏与 ModuleStatus::ERROR 冲突
#undef ERROR

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

using namespace ctfir;

// ---------------- 共享状态 ----------------
static std::mutex g_mtx;
static std::unique_ptr<Session> g_sess;          // 扫描完成后持有结果
static std::vector<std::string> g_module_rows;   // 实时模块行
static std::string g_status;                     // 底部状态
static bool g_running = false;
static bool g_done = false;
static std::string g_out_dir;

static const int WM_APP_PROGRESS = WM_APP + 1;
static const int WM_APP_DONE = WM_APP + 2;
static const int WM_APP_STATUS = WM_APP + 3;

// 控件 ID
enum {
    IDC_OUT = 100, IDC_BROWSE, IDC_SCAN, IDC_CANCEL, IDC_OPENOUT,
    IDC_LST_MOD, IDC_LST_FIND, IDC_DETAIL, IDC_COPY, IDC_LOG,
    IDC_STATIC_INFO = 200
};

static HWND g_hwnd, g_lst_mod, g_lst_find, g_detail, g_log, g_btn_scan, g_btn_cancel, g_out_edit;
static HFONT g_font;

// ---------------- ListView 助手 ----------------
static HWND make_list(HWND parent, int id, int x, int y, int w, int h) {
    HWND lv = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL,
                              x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    return lv;
}

static void lv_col(HWND lv, int idx, const wchar_t* title, int width) {
    LVCOLUMNW c{};
    c.mask = LVCF_TEXT | LVCF_WIDTH;
    c.pszText = const_cast<LPWSTR>(title);
    c.cx = width;
    ListView_InsertColumn(lv, idx, &c);
}

static int lv_row(HWND lv, const std::vector<std::wstring>& cells) {
    LVITEMW it{};
    it.mask = LVIF_TEXT;
    it.iItem = ListView_GetItemCount(lv);
    it.pszText = const_cast<LPWSTR>(cells[0].c_str());
    int row = ListView_InsertItem(lv, &it);
    for (size_t i = 1; i < cells.size(); ++i) {
        ListView_SetItemText(lv, row, static_cast<int>(i), const_cast<LPWSTR>(cells[i].c_str()));
    }
    return row;
}

static std::wstring utf8_to_w(const std::string& s) {
    if (s.empty()) return L"";
    int need = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(need > 0 ? need : 0, 0);
    if (need > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), need);
    return w;
}

static std::string w_to_utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int need = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(need > 0 ? need : 0, 0);
    if (need > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), need, nullptr, nullptr);
    return s;
}

static void set_text(HWND h, const std::string& utf8) {
    SetWindowTextW(h, utf8_to_w(utf8).c_str());
}

static void append_log(const std::string& line) {
    int len = GetWindowTextLengthW(g_log);
    SendMessageW(g_log, EM_SETSEL, len, len);
    std::wstring w = utf8_to_w(line) + L"\r\n";
    SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)w.c_str());
}

// ---------------- 扫描线程 ----------------
static void on_event(const std::string& ev, const std::string& module, const std::string& detail) {
    std::string row;
    if (ev == "module_start") {
        row = module + " | RUNNING | ...";
    } else if (ev == "module_end") {
        row = module + " | " + detail;
    } else {
        return;
    }
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_module_rows.push_back(row);
        g_status = "正在扫描: " + module;
    }
    PostMessageW(g_hwnd, WM_APP_PROGRESS, 0, 0);
}

static DWORD WINAPI scan_thread(LPVOID) {
    ScanConfig cfg;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        cfg.out_dir = g_out_dir;
        g_module_rows.clear();
        g_status = "准备会话...";
    }
    Session* s = new Session(cfg);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_sess.reset(s);
        g_sess->event_hook = on_event;
    }
    s->set_host_info(detect_os_name(), detect_os_version(), detect_os_arch(), detect_privilege());
    std::string reason;
    if (!s->prepare_out_dir(reason)) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_status = "输出目录不可写: " + cfg.out_dir;
        PostMessageW(g_hwnd, WM_APP_DONE, 0, 1);
        return 0;
    }
    s->run(build_platform_modules());
    bool ok = s->write_outputs(reason);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        const auto& ss = s->session();
        int findings = static_cast<int>(s->findings().size());
        int denied = 0, failed = 0;
        for (const auto& m : ss.modules) {
            if (m.status == ModuleStatus::PERMISSION_DENIED || m.status == ModuleStatus::SKIPPED) ++denied;
            if (m.status == ModuleStatus::ERROR || m.status == ModuleStatus::TIMEOUT) ++failed;
        }
        g_status = std::string("完成: ") + ss.overall_status +
                   " | 模块 " + std::to_string(ss.modules.size()) +
                   " | 线索 " + std::to_string(findings) +
                   " | 受限 " + std::to_string(denied) +
                   " | 失败 " + std::to_string(failed) +
                   (ok ? "" : (" | 输出失败: " + reason));
        if (!ok) g_status += "（" + reason + "）";
    }
    PostMessageW(g_hwnd, WM_APP_DONE, 0, 0);
    return 0;
}

// ---------------- 详情构建 ----------------
static void show_finding_detail(int row) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!g_sess || row < 0 || row >= static_cast<int>(g_sess->findings().size())) { set_text(g_detail, ""); return; }
    const Finding& f = g_sess->findings()[row];
    std::string txt = "规则: " + f.rule_id + "  风险: " + f.severity + "  置信度: " + f.confidence +
                      "\n位置: " + f.object_ref + "\n依据: " + f.rationale + "\n";
    if (!f.limitations.empty()) txt += "限制: " + join(f.limitations, "；") + "\n";
    for (const auto& e : g_sess->evidence()) {
        for (const auto& id : f.evidence_ids) {
            if (e.evidence_id == id && !e.payload.empty()) {
                txt += "\n--- 证据 " + e.evidence_id + "（" + e.source_path + "）---\n" +
                       e.payload.substr(0, 4000) + "\n";
            }
        }
    }
    const Advice* a = find_advice(f.advice_id);
    if (a) txt += std::string("\n--- 建议（复制参考，工具不执行）---\n【") + a->title + "】\n" + a->text;
    else txt += "\n(未挂接建议：按证据人工复核)";
    set_text(g_detail, txt);
}

static void copy_advice_to_clipboard(int row) {
    std::string txt;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!g_sess || row < 0 || row >= static_cast<int>(g_sess->findings().size())) return;
        const Advice* a = find_advice(g_sess->findings()[row].advice_id);
        txt = a ? (std::string("【") + a->title + "】\n" + a->text +
                   "\n（ctfir 只读工具：以上为人工处置参考，不自动执行）")
               : "（该发现未挂接建议：按证据人工复核）";
    }
    std::wstring w = utf8_to_w(txt);
    if (!OpenClipboard(g_hwnd)) return;
    EmptyClipboard();
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    if (hg) {
        memcpy(GlobalLock(hg), w.c_str(), (w.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(hg);
        SetClipboardData(CF_UNICODETEXT, hg);
    }
    CloseClipboard();
    append_log("[ui] 建议已复制到剪贴板");
}

// ---------------- WndProc ----------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        g_font = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        // 顶栏信息
        std::string info = detect_os_name() + " " + detect_os_version() + " [" + detect_os_arch() +
                           "]  权限: " + detect_privilege() +
                           "  [离线]  [只读模式——本工具不修改系统]";
        HWND hinfo = CreateWindowExW(0, L"STATIC", utf8_to_w(info).c_str(),
                                     WS_CHILD | WS_VISIBLE, 10, 8, 880, 22, hwnd,
                                     (HMENU)(INT_PTR)IDC_STATIC_INFO, nullptr, nullptr);
        // 输出目录
        CreateWindowExW(0, L"STATIC", L"输出目录:", WS_CHILD | WS_VISIBLE, 10, 36, 60, 20, hwnd, nullptr, nullptr, nullptr);
        g_out_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                     72, 34, 480, 22, hwnd, (HMENU)(INT_PTR)IDC_OUT, nullptr, nullptr);
        CreateWindowExW(0, L"BUTTON", L"浏览...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                        560, 33, 70, 24, hwnd, (HMENU)(INT_PTR)IDC_BROWSE, nullptr, nullptr);
        g_btn_scan = CreateWindowExW(0, L"BUTTON", L"开始只读扫描", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                     640, 33, 110, 24, hwnd, (HMENU)(INT_PTR)IDC_SCAN, nullptr, nullptr);
        g_btn_cancel = CreateWindowExW(0, L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
                                       756, 33, 60, 24, hwnd, (HMENU)(INT_PTR)IDC_CANCEL, nullptr, nullptr);
        CreateWindowExW(0, L"BUTTON", L"打开报告目录", WS_CHILD | WS_VISIBLE,
                        820, 33, 90, 24, hwnd, (HMENU)(INT_PTR)IDC_OPENOUT, nullptr, nullptr);
        // 模块列表
        CreateWindowExW(0, L"STATIC", L"检查模块（范围/状态）:", WS_CHILD | WS_VISIBLE, 10, 64, 200, 18, hwnd, nullptr, nullptr, nullptr);
        g_lst_mod = make_list(hwnd, IDC_LST_MOD, 10, 82, 900, 140);
        lv_col(g_lst_mod, 0, L"模块", 130);
        lv_col(g_lst_mod, 1, L"状态", 120);
        lv_col(g_lst_mod, 2, L"耗时", 60);
        lv_col(g_lst_mod, 3, L"线索", 50);
        lv_col(g_lst_mod, 4, L"说明", 520);
        // 发现列表
        CreateWindowExW(0, L"STATIC", L"发现（点击查看证据与建议）:", WS_CHILD | WS_VISIBLE, 10, 228, 260, 18, hwnd, nullptr, nullptr, nullptr);
        g_lst_find = make_list(hwnd, IDC_LST_FIND, 10, 246, 900, 130);
        lv_col(g_lst_find, 0, L"规则ID", 180);
        lv_col(g_lst_find, 1, L"风险", 50);
        lv_col(g_lst_find, 2, L"置信度", 60);
        lv_col(g_lst_find, 3, L"位置", 250);
        lv_col(g_lst_find, 4, L"依据", 340);
        // 详情
        CreateWindowExW(0, L"STATIC", L"详情（证据/复核/建议）:", WS_CHILD | WS_VISIBLE, 10, 382, 200, 18, hwnd, nullptr, nullptr, nullptr);
        CreateWindowExW(0, L"BUTTON", L"复制建议", WS_CHILD | WS_VISIBLE, 846, 379, 64, 22, hwnd, (HMENU)(INT_PTR)IDC_COPY, nullptr, nullptr);
        g_detail = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                                   10, 400, 900, 130, hwnd, (HMENU)(INT_PTR)IDC_DETAIL, nullptr, nullptr);
        // 日志
        CreateWindowExW(0, L"STATIC", L"日志:", WS_CHILD | WS_VISIBLE, 10, 536, 60, 16, hwnd, nullptr, nullptr, nullptr);
        g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                                10, 552, 900, 70, hwnd, (HMENU)(INT_PTR)IDC_LOG, nullptr, nullptr);
        // 默认输出目录
        char tmp[MAX_PATH]{};
        GetTempPathA(MAX_PATH, tmp);
        std::string def = std::string(tmp) + "ctfir-out";
        set_text(g_out_edit, def);
        // 字体
        EnumChildWindows(hwnd, [](HWND h, LPARAM lp) -> BOOL {
            SendMessageW(h, WM_SETFONT, (WPARAM)lp, TRUE);
            return TRUE;
        }, (LPARAM)g_font);
        append_log("[init] ctfir 只读应急助手就绪（本工具仅扫描与建议，不修改系统）");
        return 0;
    }
    case WM_APP_PROGRESS: {
        std::vector<std::string> rows;
        std::string status;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            rows = g_module_rows;
            status = g_status;
        }
        ListView_DeleteAllItems(g_lst_mod);
        for (const auto& r : rows) {
            size_t p1 = r.find(" | ");
            std::string mod = p1 == std::string::npos ? r : r.substr(0, p1);
            std::string rest = p1 == std::string::npos ? "" : r.substr(p1 + 3);
            lv_row(g_lst_mod, {utf8_to_w(mod), utf8_to_w(rest), L"", L"", L""});
        }
        append_log(status);
        return 0;
    }
    case WM_APP_DONE: {
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            g_running = false;
            g_done = true;
            g_status = "完成: " + (g_sess ? g_sess->session().overall_status : "?");
        }
        EnableWindow(g_btn_scan, TRUE);
        EnableWindow(g_btn_cancel, FALSE);
        // 填充模块与发现（独立锁作用域；避免与 show_finding_detail 重入）
        ListView_DeleteAllItems(g_lst_mod);
        ListView_DeleteAllItems(g_lst_find);
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            if (g_sess) {
                for (const auto& m : g_sess->session().modules) {
                    std::string note = m.status_note;
                    if (!m.omitted_sources.empty())
                        note += " 漏项x" + std::to_string(m.omitted_sources.size());
                    lv_row(g_lst_mod, {utf8_to_w(m.module_id),
                                       utf8_to_w(module_status_str(m.status)),
                                       utf8_to_w(std::to_string(static_cast<long long>(m.elapsed_ms)) + "ms"),
                                       utf8_to_w(m.has_findings ? "有" : "-"),
                                       utf8_to_w(note.substr(0, 200))});
                }
                for (const auto& f : g_sess->findings()) {
                    lv_row(g_lst_find, {utf8_to_w(f.rule_id), utf8_to_w(f.severity),
                                        utf8_to_w(f.confidence), utf8_to_w(f.object_ref),
                                        utf8_to_w(f.rationale.substr(0, 160))});
                }
                append_log("报告已写入: " + g_out_dir + "（report.html / session.json / findings.json）");
            }
        }
        // 有发现时自动选中首条，直接展示证据与建议
        if (ListView_GetItemCount(g_lst_find) > 0) {
            ListView_SetItemState(g_lst_find, 0, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
        }
        return 0;
    }
    case WM_APP_STATUS: {
        std::string status;
        { std::lock_guard<std::mutex> lk(g_mtx); status = g_status; }
        append_log(status);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_BROWSE) {
            BROWSEINFOA bi{};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = "选择报告输出目录";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            PIDLIST_ABSOLUTE rl = SHBrowseForFolderA(&bi);
            if (rl) {
                char path[MAX_PATH]{};
                if (SHGetPathFromIDListA(rl, path)) set_text(g_out_edit, path);
                CoTaskMemFree(rl);
            }
            return 0;
        }
        if (id == IDC_SCAN && !g_running) {
            char dir[MAX_PATH]{};
            GetWindowTextA(g_out_edit, dir, MAX_PATH);
            if (!dir[0]) { MessageBoxW(hwnd, L"请先选择输出目录", L"提示", MB_OK); return 0; }
            {
                std::lock_guard<std::mutex> lk(g_mtx);
                g_out_dir = dir;
                g_running = true;
                g_done = false;
            }
            EnableWindow(g_btn_scan, FALSE);
            EnableWindow(g_btn_cancel, TRUE);
            append_log("[scan] 开始只读扫描 → " + std::string(dir));
            CreateThread(nullptr, 0, scan_thread, nullptr, 0, nullptr);
            return 0;
        }
        if (id == IDC_CANCEL && g_running) {
            std::lock_guard<std::mutex> lk(g_mtx);
            if (g_sess) g_sess->request_cancel();
            append_log("[ui] 已请求取消（将保留已完成部分）");
            return 0;
        }
        if (id == IDC_OPENOUT) {
            char dir[MAX_PATH]{};
            GetWindowTextA(g_out_edit, dir, MAX_PATH);
            ShellExecuteA(hwnd, "explore", dir, nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        }
        if (id == IDC_COPY) {
            int row = ListView_GetSelectionMark(g_lst_find);
            if (row < 0) row = ListView_GetNextItem(g_lst_find, -1, LVNI_SELECTED);
            copy_advice_to_clipboard(row);
            return 0;
        }
        return 0;
    }
    case WM_NOTIFY: {
        NMHDR* nm = (NMHDR*)lp;
        if (nm->idFrom == IDC_LST_FIND && nm->code == LVN_ITEMCHANGED) {
            NMLISTVIEW* nl = (NMLISTVIEW*)lp;
            if (nl->uNewState & LVIS_SELECTED) show_finding_detail(nl->iItem);
        }
        return 0;
    }
    case WM_TIMER:
        if (wp == 999) { PostQuitMessage(0); return 0; } // selftest 1.5s 自退
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    BOOL selftest = FALSE;
    BOOL autostart = FALSE;
    wchar_t outPath[MAX_PATH] = L"";
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (lstrcmpiW(argv[i], L"--selftest") == 0) selftest = TRUE;
            else if (lstrcmpiW(argv[i], L"--scan") == 0) autostart = TRUE;
            else if (lstrcmpiW(argv[i], L"--out") == 0 && i + 1 < argc) {
                lstrcpynW(outPath, argv[i + 1], MAX_PATH);
                ++i;
            }
        }
        LocalFree(argv);
    }

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&icc);

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"CTFIR_GUI_MAIN";
    if (!RegisterClassW(&wc)) return 10;

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"ctfir — CTF 只读应急助手",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                940, 680, nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 11;
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);
    if (selftest) SetTimer(hwnd, 999, 1500, nullptr);
    if (autostart) PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(IDC_SCAN, 0), 0);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    DestroyWindow(hwnd);

    if (selftest && outPath[0]) {
        FILE* f = _wfopen(outPath, L"w");
        if (f) {
            fprintf(f, "ctfir-gui-selftest OK window_created=1 modules=%d\n",
                    static_cast<int>(build_platform_modules().size()));
            fclose(f);
        }
    }
    return 0;
}
