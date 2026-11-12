// ctfir-gui — Win32 原生只读应急工作台（v0.7）
// 纪律：扫描在后台线程；UI 只读展示；无任何修复/执行入口；双击不运行证据。
#include "core/model.hpp"
#include "core/session.hpp"
#include "core/report.hpp"
#include "core/advice.hpp"
#include "core/util.hpp"
#include "core/triage.hpp"
#include "core/display_action.hpp"
#include "core/compat.hpp"
#include "platform/modules_registry.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#undef ERROR

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace ctfir;

static std::recursive_mutex g_mtx;
static std::unique_ptr<Session> g_sess;
static std::vector<std::string> g_module_rows;
static std::string g_scan_msg;
static bool g_running = false;
static std::string g_out_dir;

static const int WM_APP_PROGRESS = WM_APP + 1;
static const int WM_APP_DONE = WM_APP + 2;

enum {
    IDC_OUT = 100, IDC_BROWSE, IDC_SCAN, IDC_CANCEL, IDC_OPENOUT,
    IDC_LST_MOD, IDC_LST_FIND, IDC_DETAIL, IDC_LOG,
    IDC_COPY_CMD, IDC_COPY_ADV, IDC_COPY_ALL,
    IDC_VIEW, IDC_CAT, IDC_SEV, IDC_SEARCH,
    IDC_TABS, IDC_KPI, IDC_HEADER, IDC_SUB, IDC_STATUS
};

static HWND g_hwnd, g_header, g_sub, g_kpi, g_stbar;
static HWND g_out_edit, g_btn_scan, g_btn_cancel;
static HWND g_cmb_view, g_cmb_cat, g_cmb_sev, g_search;
static HWND g_tabs, g_lst_mod, g_lst_find, g_detail, g_log;
static HFONT g_font, g_font_title, g_font_mono;
static HBRUSH g_br_header, g_br_bg;
static int g_sort_col = -1;
static bool g_sort_asc = true;
static int g_tab = 0;

static const COLORREF COL_HEADER = RGB(15, 39, 68);
static const COLORREF COL_BG = RGB(244, 246, 248);
static const COLORREF COL_HIGH = RGB(225, 29, 72);
static const COLORREF COL_MED = RGB(217, 119, 6);
static const COLORREF COL_LOW = RGB(202, 138, 4);
static const COLORREF COL_INFO = RGB(100, 116, 139);

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
static std::string get_text(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring w(n, 0);
    GetWindowTextW(h, w.data(), n + 1);
    return w_to_utf8(w);
}
static HFONT make_font(int px, int weight, const wchar_t* name) {
    return CreateFontW(-px, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, name);
}

static HWND make_list(HWND parent, int id) {
    HWND lv = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                              0, 0, 10, 10, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    ListView_SetBkColor(lv, RGB(255, 255, 255));
    ListView_SetTextBkColor(lv, RGB(255, 255, 255));
    ListView_SetTextColor(lv, RGB(15, 23, 42));
    return lv;
}
static void lv_col(HWND lv, int idx, const wchar_t* title, int width) {
    LVCOLUMNW c{};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    c.pszText = const_cast<LPWSTR>(title);
    c.cx = width;
    c.fmt = LVCFMT_LEFT;
    ListView_InsertColumn(lv, idx, &c);
}
static int lv_row(HWND lv, const std::vector<std::wstring>& cells, LPARAM data) {
    LVITEMW it{};
    it.mask = LVIF_TEXT | LVIF_PARAM;
    it.iItem = ListView_GetItemCount(lv);
    it.pszText = const_cast<LPWSTR>(cells[0].c_str());
    it.lParam = data;
    int row = ListView_InsertItem(lv, &it);
    for (size_t i = 1; i < cells.size(); ++i)
        ListView_SetItemText(lv, row, static_cast<int>(i), const_cast<LPWSTR>(cells[i].c_str()));
    return row;
}

static void combo_add(HWND cb, const wchar_t* text, LPARAM data) {
    int i = (int)SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)text);
    SendMessageW(cb, CB_SETITEMDATA, i, data);
}
static LPARAM combo_data(HWND cb) {
    int i = (int)SendMessageW(cb, CB_GETCURSEL, 0, 0);
    if (i < 0) return 0;
    return SendMessageW(cb, CB_GETITEMDATA, i, 0);
}

static void append_log(const std::string& line) {
    if (!g_log) return;
    int len = GetWindowTextLengthW(g_log);
    SendMessageW(g_log, EM_SETSEL, len, len);
    std::wstring w = utf8_to_w(line) + L"\r\n";
    SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)w.c_str());
}

static void on_event(const std::string& ev, const std::string& module, const std::string& detail) {
    std::string row;
    if (ev == "module_start") row = module + " | RUNNING | ...";
    else if (ev == "module_end") row = module + " | " + detail;
    else return;
    {
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        g_module_rows.push_back(row);
        g_scan_msg = "正在扫描: " + module;
    }
    PostMessageW(g_hwnd, WM_APP_PROGRESS, 0, 0);
}

static DWORD WINAPI scan_thread(LPVOID) {
    ScanConfig cfg;
    {
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        cfg.out_dir = g_out_dir;
        g_module_rows.clear();
        g_scan_msg = "准备会话...";
    }
    Session* s = new Session(cfg);
    {
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        g_sess.reset(s);
        g_sess->event_hook = on_event;
    }
    s->set_host_info(detect_os_name(), detect_os_version(), detect_os_arch(), detect_privilege());
    std::string reason;
    if (!s->prepare_out_dir(reason)) {
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        g_scan_msg = "输出目录不可写: " + cfg.out_dir;
        PostMessageW(g_hwnd, WM_APP_DONE, 0, 1);
        return 0;
    }
    s->run(build_platform_modules());
    bool ok = s->write_outputs(reason);
    {
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        const auto& ss = s->session();
        int findings = static_cast<int>(s->findings().size());
        g_scan_msg = std::string("完成: ") + ss.overall_status +
                   " | 模块 " + std::to_string(ss.modules.size()) +
                   " | 线索 " + std::to_string(findings) +
                   (ok ? "" : (" | 输出失败: " + reason));
    }
    PostMessageW(g_hwnd, WM_APP_DONE, 0, 0);
    return 0;
}

static std::string sev_zh(const std::string& s) {
    if (s == "high") return "高";
    if (s == "medium") return "中";
    if (s == "low") return "低";
    if (s == "info") return "信息";
    return s;
}

static void update_kpi() {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    if (!g_sess) { set_text(g_kpi, "立刻清 0   再加固 0   溯源 0   Web 0   已隐藏清单 0"); return; }
    KpiCounts k = count_kpi(g_sess->findings());
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "立刻清 %d    再加固 %d    溯源 %d    Web %d    已隐藏清单 %d    合计 %d",
                  k.clear, k.harden, k.trace, k.web, k.inventory, k.total);
    set_text(g_kpi, buf);
}

static ViewPreset current_view() {
    LPARAM d = combo_data(g_cmb_view);
    if (d == 2) return ViewPreset::All;
    if (d == 1) return ViewPreset::Team;
    return ViewPreset::Personal;
}
static std::string current_cat() {
    LPARAM d = combo_data(g_cmb_cat);
    if (d == 1) return "clear";
    if (d == 2) return "harden";
    if (d == 3) return "trace";
    if (d == 4) return "web";
    if (d == 5) return "inventory";
    return "all";
}
static std::string current_sev() {
    LPARAM d = combo_data(g_cmb_sev);
    if (d == 1) return "high";
    if (d == 2) return "medium";
    if (d == 3) return "low";
    if (d == 4) return "info";
    return "all";
}

static int selected_finding_index() {
    int row = ListView_GetNextItem(g_lst_find, -1, LVNI_SELECTED);
    if (row < 0) return -1;
    LVITEMW it{};
    it.mask = LVIF_PARAM;
    it.iItem = row;
    if (!ListView_GetItem(g_lst_find, &it)) return -1;
    return static_cast<int>(it.lParam);
}

static void refill_findings() {
    ListView_DeleteAllItems(g_lst_find);
    ViewPreset view = current_view();
    std::string cat = current_cat();
    std::string sev = current_sev();
    std::string q = get_text(g_search);
    int shown = 0, total = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(g_mtx);
        if (!g_sess) { set_text(g_stbar, "尚未扫描"); return; }
        const auto& fds = g_sess->findings();
        total = static_cast<int>(fds.size());
        auto idx = sorted_finding_indices(fds);
        if (g_sort_col >= 0) {
            std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
                const Finding& fa = fds[a];
                const Finding& fb = fds[b];
                int c = 0;
                if (g_sort_col == 0) c = bucket_rank(bucket_of(fa)) - bucket_rank(bucket_of(fb));
                else if (g_sort_col == 1) c = severity_rank(fa.severity) - severity_rank(fb.severity);
                else if (g_sort_col == 2) c = title_zh_of(fa).compare(title_zh_of(fb));
                else if (g_sort_col == 3) c = fa.object_ref.compare(fb.object_ref);
                else c = display_action(fa).command.compare(display_action(fb).command);
                if (c == 0) return a < b;
                return g_sort_asc ? c < 0 : c > 0;
            });
        }
        for (auto i : idx) {
            const Finding& f = fds[i];
            if (!finding_visible(f, view, cat, sev, q)) continue;
            Triage t = triage_of(f);
            DisplayAction da = display_action(f);
            std::string cmd = da.command;
            if (cmd.size() > 140) cmd = cmd.substr(0, 140) + "...";
            lv_row(g_lst_find, {
                utf8_to_w(t.bucket_zh), utf8_to_w(sev_zh(f.severity)),
                utf8_to_w(da.title), utf8_to_w(f.object_ref), utf8_to_w(cmd)
            }, static_cast<LPARAM>(i));
            ++shown;
        }
    }
    char st[256];
    std::snprintf(st, sizeof(st), "显示 %d / %d    点「全部」找回清单/事实项    只读·不修改系统",
                  shown, total);
    set_text(g_stbar, st);
    if (shown > 0) {
        ListView_SetItemState(g_lst_find, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    } else {
        set_text(g_detail, "当前过滤下无条目。切换视图为「全部」可找回清单项。");
    }
}

static void refill_modules() {
    ListView_DeleteAllItems(g_lst_mod);
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    if (g_sess) {
        for (const auto& m : g_sess->session().modules) {
            std::string note = m.status_note;
            if (!m.omitted_sources.empty())
                note += " 漏项x" + std::to_string(m.omitted_sources.size());
            lv_row(g_lst_mod, {utf8_to_w(m.module_id),
                               utf8_to_w(module_status_str(m.status)),
                               utf8_to_w(std::to_string(static_cast<long long>(m.elapsed_ms)) + "ms"),
                               utf8_to_w(m.has_findings ? "有" : "-"),
                               utf8_to_w(note.substr(0, 200))}, 0);
        }
        return;
    }
    for (const auto& r : g_module_rows) {
        size_t p1 = r.find(" | ");
        std::string mod = p1 == std::string::npos ? r : r.substr(0, p1);
        std::string rest = p1 == std::string::npos ? "" : r.substr(p1 + 3);
        lv_row(g_lst_mod, {utf8_to_w(mod), utf8_to_w(rest), L"", L"", L""}, 0);
    }
}

static void show_finding_detail(int fi) {
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    if (!g_sess || fi < 0 || fi >= static_cast<int>(g_sess->findings().size())) {
        set_text(g_detail, "");
        return;
    }
    const Finding& f = g_sess->findings()[fi];
    DisplayAction da = display_action(f);
    std::string txt = da.title + "\r\n规则: " + f.rule_id + "  风险: " + f.severity +
                      "  置信度: " + f.confidence + "\r\n位置: " + f.object_ref +
                      "\r\n\r\n【一条命令】\r\n" + da.command + "\r\n";
    if (!da.contest_note.empty()) txt += "\r\n" + da.contest_note + "\r\n";
    txt += "\r\n依据: " + f.rationale + "\r\n";
    if (!f.limitations.empty()) txt += "限制: " + join(f.limitations, "；") + "\r\n";
    for (const auto& e : g_sess->evidence()) {
        for (const auto& id : f.evidence_ids) {
            if (e.evidence_id == id && !e.payload.empty()) {
                txt += "\r\n--- 证据 " + e.evidence_id + "（" + e.source_path + "）---\r\n" +
                       e.payload.substr(0, 4000) + "\r\n";
            }
        }
    }
    txt += "\r\n--- 手册（工具不执行）---\r\n" + instantiate_advice_body(f);
    set_text(g_detail, txt);
}

static void clipboard_set(const std::string& utf8) {
    std::wstring w = utf8_to_w(utf8);
    if (!OpenClipboard(g_hwnd)) return;
    EmptyClipboard();
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    if (hg) {
        memcpy(GlobalLock(hg), w.c_str(), (w.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(hg);
        SetClipboardData(CF_UNICODETEXT, hg);
    }
    CloseClipboard();
    append_log("[ui] 已复制到剪贴板");
}

static void copy_selected(int kind) {
    int fi = selected_finding_index();
    std::lock_guard<std::recursive_mutex> lk(g_mtx);
    if (!g_sess || fi < 0 || fi >= static_cast<int>(g_sess->findings().size())) return;
    const Finding& f = g_sess->findings()[fi];
    if (kind == 0) clipboard_set(display_action(f).command);
    else if (kind == 1) clipboard_set(instantiate_advice_body(f));
    else clipboard_set(instantiate_advice(f));
}

static void show_tab(int tab) {
    g_tab = tab;
    ShowWindow(g_lst_find, tab == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_lst_mod, tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_log, tab == 2 ? SW_SHOW : SW_HIDE);
}

static void layout() {
    RECT rc{};
    GetClientRect(g_hwnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    const int M = 10, header = 44, tool = 32, kpi = 26, filt = 28, status = 22;
    int y = 0;
    MoveWindow(g_header, 0, y, w, header, TRUE);
    MoveWindow(g_sub, 12, 22, w - 24, 18, TRUE);
    y += header;
    MoveWindow(g_out_edit, 72, y + 4, (std::max)(120, w - 72 - 360), 22, TRUE);
    int bx = w - 348;
    // labels/buttons created at fixed-ish x; reposition buttons
    HWND browse = GetDlgItem(g_hwnd, IDC_BROWSE);
    HWND openb = GetDlgItem(g_hwnd, IDC_OPENOUT);
    HWND lbl = GetDlgItem(g_hwnd, 300);
    MoveWindow(lbl, M, y + 6, 60, 18, TRUE);
    MoveWindow(browse, bx, y + 3, 64, 24, TRUE);
    MoveWindow(g_btn_scan, bx + 68, y + 3, 100, 24, TRUE);
    MoveWindow(g_btn_cancel, bx + 172, y + 3, 56, 24, TRUE);
    MoveWindow(openb, bx + 232, y + 3, 100, 24, TRUE);
    y += tool;
    MoveWindow(g_kpi, M, y, w - 2 * M, kpi, TRUE);
    y += kpi;
    HWND lblv = GetDlgItem(g_hwnd, 301);
    HWND lblc = GetDlgItem(g_hwnd, 302);
    HWND lbls = GetDlgItem(g_hwnd, 303);
    HWND lblq = GetDlgItem(g_hwnd, 304);
    MoveWindow(lblv, M, y + 4, 32, 18, TRUE);
    MoveWindow(g_cmb_view, M + 32, y, 110, 200, TRUE);
    MoveWindow(lblc, M + 150, y + 4, 32, 18, TRUE);
    MoveWindow(g_cmb_cat, M + 182, y, 110, 200, TRUE);
    MoveWindow(lbls, M + 300, y + 4, 32, 18, TRUE);
    MoveWindow(g_cmb_sev, M + 332, y, 80, 200, TRUE);
    MoveWindow(lblq, M + 420, y + 4, 32, 18, TRUE);
    MoveWindow(g_search, M + 452, y, (std::max)(80, w - M - 452 - M), 22, TRUE);
    y += filt;
    MoveWindow(g_tabs, M, y, w - 2 * M, 24, TRUE);
    y += 24;
    int detail_h = (std::max)(90, (h - y - status - 28) * 38 / 100);
    int list_h = (std::max)(80, h - y - status - 28 - detail_h);
    MoveWindow(g_lst_find, M, y, w - 2 * M, list_h, TRUE);
    MoveWindow(g_lst_mod, M, y, w - 2 * M, list_h, TRUE);
    MoveWindow(g_log, M, y, w - 2 * M, list_h, TRUE);
    y += list_h + 4;
    HWND c1 = GetDlgItem(g_hwnd, IDC_COPY_CMD);
    HWND c2 = GetDlgItem(g_hwnd, IDC_COPY_ADV);
    HWND c3 = GetDlgItem(g_hwnd, IDC_COPY_ALL);
    HWND dlbl = GetDlgItem(g_hwnd, 305);
    MoveWindow(dlbl, M, y, 200, 18, TRUE);
    MoveWindow(c1, w - M - 240, y - 2, 76, 22, TRUE);
    MoveWindow(c2, w - M - 160, y - 2, 76, 22, TRUE);
    MoveWindow(c3, w - M - 80, y - 2, 76, 22, TRUE);
    y += 22;
    MoveWindow(g_detail, M, y, w - 2 * M, detail_h, TRUE);
    MoveWindow(g_stbar, 0, h - status, w, status, TRUE);
    if (g_lst_find) {
        int rest = (std::max)(220, w - 2 * M - 72 - 48 - 200 - 240 - 28);
        ListView_SetColumnWidth(g_lst_find, 4, rest);
        ListView_SetColumnWidth(g_lst_mod, 4, (std::max)(180, w - 2 * M - 140 - 120 - 70 - 50 - 28));
    }
}

static HWND make_btn(HWND p, int id, const wchar_t* t) {
    return CreateWindowExW(0, L"BUTTON", t, WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                           0, 0, 70, 24, p, (HMENU)(INT_PTR)id, nullptr, nullptr);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        g_br_header = CreateSolidBrush(COL_HEADER);
        g_br_bg = CreateSolidBrush(COL_BG);
        g_font_title = make_font(16, FW_SEMIBOLD, L"Microsoft YaHei UI");
        if (!g_font_title) g_font_title = make_font(16, FW_SEMIBOLD, L"Microsoft YaHei");
        g_font = make_font(13, FW_NORMAL, L"Microsoft YaHei UI");
        if (!g_font) g_font = make_font(13, FW_NORMAL, L"Microsoft YaHei");
        if (!g_font) g_font = make_font(13, FW_NORMAL, L"MS Shell Dlg 2");
        g_font_mono = make_font(12, FW_NORMAL, L"Consolas");
        if (!g_font_mono) g_font_mono = g_font;

        std::wstring hdr = L"ctfir  只读应急工作台  ·  v";
        hdr += utf8_to_w(kToolVersion);
        g_header = CreateWindowExW(0, L"STATIC", hdr.c_str(),
                                   WS_CHILD | WS_VISIBLE, 12, 6, 560, 20, hwnd,
                                   (HMENU)(INT_PTR)IDC_HEADER, nullptr, nullptr);
        std::string sub = detect_os_name() + " " + detect_os_version() + " [" + detect_os_arch() +
                          "]   权限: " + detect_privilege() + "   离线 · 只读 · 工具不修改系统";
        HostCompat hc = evaluate_host_compat();
        if (hc.level == "warn" && !hc.note.empty())
            sub += "   兼容性: " + hc.note;
        g_sub = CreateWindowExW(0, L"STATIC", utf8_to_w(sub).c_str(),
                                WS_CHILD | WS_VISIBLE, 12, 24, 800, 16, hwnd,
                                (HMENU)(INT_PTR)IDC_SUB, nullptr, nullptr);
        if (hc.level == "warn" && !hc.note.empty())
            MessageBoxW(hwnd, utf8_to_w(hc.note).c_str(), L"ctfir 兼容性提示", MB_OK | MB_ICONWARNING);

        CreateWindowExW(0, L"STATIC", L"输出目录", WS_CHILD | WS_VISIBLE, 10, 50, 60, 18, hwnd,
                        (HMENU)300, nullptr, nullptr);
        g_out_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                     72, 48, 400, 22, hwnd, (HMENU)(INT_PTR)IDC_OUT, nullptr, nullptr);
        make_btn(hwnd, IDC_BROWSE, L"浏览...");
        g_btn_scan = CreateWindowExW(0, L"BUTTON", L"开始只读扫描",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                       0, 0, 100, 24, hwnd, (HMENU)(INT_PTR)IDC_SCAN, nullptr, nullptr);
        g_btn_cancel = CreateWindowExW(0, L"BUTTON", L"取消",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
                                       0, 0, 56, 24, hwnd, (HMENU)(INT_PTR)IDC_CANCEL, nullptr, nullptr);
        make_btn(hwnd, IDC_OPENOUT, L"打开报告目录");

        g_kpi = CreateWindowExW(0, L"STATIC", L"立刻清 0    再加固 0    溯源 0    Web 0    已隐藏清单 0",
                                WS_CHILD | WS_VISIBLE, 10, 80, 800, 20, hwnd,
                                (HMENU)(INT_PTR)IDC_KPI, nullptr, nullptr);

        CreateWindowExW(0, L"STATIC", L"视图", WS_CHILD | WS_VISIBLE, 0, 0, 32, 18, hwnd, (HMENU)301, nullptr, nullptr);
        CreateWindowExW(0, L"STATIC", L"类别", WS_CHILD | WS_VISIBLE, 0, 0, 32, 18, hwnd, (HMENU)302, nullptr, nullptr);
        CreateWindowExW(0, L"STATIC", L"风险", WS_CHILD | WS_VISIBLE, 0, 0, 32, 18, hwnd, (HMENU)303, nullptr, nullptr);
        CreateWindowExW(0, L"STATIC", L"搜索", WS_CHILD | WS_VISIBLE, 0, 0, 32, 18, hwnd, (HMENU)304, nullptr, nullptr);
        auto mkcb = [&](int id) {
            return CreateWindowExW(0, L"COMBOBOX", L"",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                   0, 0, 100, 200, hwnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
        };
        g_cmb_view = mkcb(IDC_VIEW);
        g_cmb_cat = mkcb(IDC_CAT);
        g_cmb_sev = mkcb(IDC_SEV);
        combo_add(g_cmb_view, L"个人防护", 0);
        combo_add(g_cmb_view, L"团队综合", 1);
        combo_add(g_cmb_view, L"全部", 2);
        SendMessageW(g_cmb_view, CB_SETCURSEL, 0, 0);
        combo_add(g_cmb_cat, L"全部类别", 0);
        combo_add(g_cmb_cat, L"立刻清", 1);
        combo_add(g_cmb_cat, L"再加固", 2);
        combo_add(g_cmb_cat, L"溯源", 3);
        combo_add(g_cmb_cat, L"Web/中间件", 4);
        combo_add(g_cmb_cat, L"清单/事实", 5);
        SendMessageW(g_cmb_cat, CB_SETCURSEL, 0, 0);
        combo_add(g_cmb_sev, L"全部风险", 0);
        combo_add(g_cmb_sev, L"高", 1);
        combo_add(g_cmb_sev, L"中", 2);
        combo_add(g_cmb_sev, L"低", 3);
        combo_add(g_cmb_sev, L"信息", 4);
        SendMessageW(g_cmb_sev, CB_SETCURSEL, 0, 0);
        g_search = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                   0, 0, 200, 22, hwnd, (HMENU)(INT_PTR)IDC_SEARCH, nullptr, nullptr);

        g_tabs = CreateWindowExW(0, WC_TABCONTROLW, L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                 0, 0, 100, 24, hwnd, (HMENU)(INT_PTR)IDC_TABS, nullptr, nullptr);
        TCITEMW ti{};
        ti.mask = TCIF_TEXT;
        ti.pszText = const_cast<LPWSTR>(L"处置");
        TabCtrl_InsertItem(g_tabs, 0, &ti);
        ti.pszText = const_cast<LPWSTR>(L"模块");
        TabCtrl_InsertItem(g_tabs, 1, &ti);
        ti.pszText = const_cast<LPWSTR>(L"日志");
        TabCtrl_InsertItem(g_tabs, 2, &ti);

        g_lst_find = make_list(hwnd, IDC_LST_FIND);
        lv_col(g_lst_find, 0, L"优先级", 72);
        lv_col(g_lst_find, 1, L"风险", 48);
        lv_col(g_lst_find, 2, L"问题", 200);
        lv_col(g_lst_find, 3, L"对象", 240);
        lv_col(g_lst_find, 4, L"一条命令", 360);
        g_lst_mod = make_list(hwnd, IDC_LST_MOD);
        lv_col(g_lst_mod, 0, L"模块", 140);
        lv_col(g_lst_mod, 1, L"状态", 120);
        lv_col(g_lst_mod, 2, L"耗时", 70);
        lv_col(g_lst_mod, 3, L"线索", 50);
        lv_col(g_lst_mod, 4, L"说明", 480);
        ShowWindow(g_lst_mod, SW_HIDE);
        g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | ES_MULTILINE | ES_READONLY | WS_VSCROLL | WS_HSCROLL,
                                0, 0, 100, 40, hwnd, (HMENU)(INT_PTR)IDC_LOG, nullptr, nullptr);

        CreateWindowExW(0, L"STATIC", L"详情（命令 / 证据 / 手册）", WS_CHILD | WS_VISIBLE,
                        0, 0, 200, 18, hwnd, (HMENU)305, nullptr, nullptr);
        make_btn(hwnd, IDC_COPY_CMD, L"复制命令");
        make_btn(hwnd, IDC_COPY_ADV, L"复制手册");
        make_btn(hwnd, IDC_COPY_ALL, L"复制全部");
        g_detail = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                                   0, 0, 100, 80, hwnd, (HMENU)(INT_PTR)IDC_DETAIL, nullptr, nullptr);
        g_stbar = CreateWindowExW(0, L"STATIC", L"就绪 · 只读模式 · 个人防护默认隐藏清单/事实",
                                   WS_CHILD | WS_VISIBLE,
                                   0, 0, 100, 22, hwnd, (HMENU)(INT_PTR)IDC_STATUS, nullptr, nullptr);

        char tmp[MAX_PATH]{};
        GetTempPathA(MAX_PATH, tmp);
        set_text(g_out_edit, std::string(tmp) + "ctfir-out");

        EnumChildWindows(hwnd, [](HWND h, LPARAM lp) -> BOOL {
            SendMessageW(h, WM_SETFONT, (WPARAM)lp, TRUE);
            return TRUE;
        }, (LPARAM)g_font);
        SendMessageW(g_header, WM_SETFONT, (WPARAM)g_font_title, TRUE);
        SendMessageW(g_kpi, WM_SETFONT, (WPARAM)g_font_title, TRUE);
        SendMessageW(g_detail, WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_log, WM_SETFONT, (WPARAM)g_font_mono, TRUE);
        SendMessageW(g_stbar, WM_SETFONT, (WPARAM)g_font, TRUE);
        append_log("[init] ctfir 只读应急工作台就绪（仅扫描与建议，不修改系统）");
        layout();
        return 0;
    }
    case WM_SIZE:
        layout();
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* m = (MINMAXINFO*)lp;
        m->ptMinTrackSize.x = 940;
        m->ptMinTrackSize.y = 600;
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        HWND ctl = (HWND)lp;
        if (ctl == g_header || ctl == g_sub || ctl == g_stbar) {
            SetTextColor(dc, RGB(255, 255, 255));
            SetBkMode(dc, TRANSPARENT);
            SetBkColor(dc, COL_HEADER);
            return (LRESULT)g_br_header;
        }
        if (ctl == g_kpi) {
            SetTextColor(dc, RGB(15, 39, 68));
            SetBkMode(dc, TRANSPARENT);
            SetBkColor(dc, COL_BG);
            return (LRESULT)g_br_bg;
        }
        SetBkColor(dc, COL_BG);
        return (LRESULT)g_br_bg;
    }
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect((HDC)wp, &rc, g_br_bg);
        RECT hdr = rc; hdr.bottom = 44;
        FillRect((HDC)wp, &hdr, g_br_header);
        RECT st = rc; st.top = rc.bottom - 22;
        FillRect((HDC)wp, &st, g_br_header);
        return 1;
    }
    case WM_APP_PROGRESS: {
        std::string status;
        { std::lock_guard<std::recursive_mutex> lk(g_mtx); status = g_scan_msg; }
        refill_modules();
        set_text(g_stbar, status);
        append_log(status);
        return 0;
    }
    case WM_APP_DONE: {
        {
            std::lock_guard<std::recursive_mutex> lk(g_mtx);
            g_running = false;
        }
        EnableWindow(g_btn_scan, TRUE);
        EnableWindow(g_btn_cancel, FALSE);
        refill_modules();
        update_kpi();
        refill_findings();
        TabCtrl_SetCurSel(g_tabs, 0);
        show_tab(0);
        append_log("报告已写入: " + g_out_dir + "（report.html / session.json / findings.json）");
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        int code = HIWORD(wp);
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
                std::lock_guard<std::recursive_mutex> lk(g_mtx);
                g_out_dir = dir;
                g_running = true;
            }
            EnableWindow(g_btn_scan, FALSE);
            EnableWindow(g_btn_cancel, TRUE);
            append_log("[scan] 开始只读扫描 → " + std::string(dir));
            TabCtrl_SetCurSel(g_tabs, 1);
            show_tab(1);
            CreateThread(nullptr, 0, scan_thread, nullptr, 0, nullptr);
            return 0;
        }
        if (id == IDC_CANCEL && g_running) {
            std::lock_guard<std::recursive_mutex> lk(g_mtx);
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
        if (id == IDC_COPY_CMD) { copy_selected(0); return 0; }
        if (id == IDC_COPY_ADV) { copy_selected(1); return 0; }
        if (id == IDC_COPY_ALL) { copy_selected(2); return 0; }
        if ((id == IDC_VIEW || id == IDC_CAT || id == IDC_SEV) && code == CBN_SELCHANGE) {
            refill_findings();
            return 0;
        }
        if (id == IDC_SEARCH && code == EN_CHANGE) {
            refill_findings();
            return 0;
        }
        return 0;
    }
    case WM_NOTIFY: {
        NMHDR* nm = (NMHDR*)lp;
        if (nm->idFrom == IDC_TABS && nm->code == TCN_SELCHANGE) {
            show_tab(TabCtrl_GetCurSel(g_tabs));
            return 0;
        }
        if (nm->idFrom == IDC_LST_FIND && nm->code == LVN_ITEMCHANGED) {
            NMLISTVIEW* nl = (NMLISTVIEW*)lp;
            if (nl->uNewState & LVIS_SELECTED) {
                LVITEMW it{};
                it.mask = LVIF_PARAM;
                it.iItem = nl->iItem;
                ListView_GetItem(g_lst_find, &it);
                show_finding_detail(static_cast<int>(it.lParam));
            }
        }
        if (nm->idFrom == IDC_LST_FIND && nm->code == LVN_COLUMNCLICK) {
            NMLISTVIEW* nl = (NMLISTVIEW*)lp;
            if (g_sort_col == nl->iSubItem) g_sort_asc = !g_sort_asc;
            else { g_sort_col = nl->iSubItem; g_sort_asc = true; }
            refill_findings();
            return 0;
        }
        if (nm->idFrom == IDC_LST_FIND && nm->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW* cd = (NMLVCUSTOMDRAW*)lp;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT)
                return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int fi = static_cast<int>(cd->nmcd.lItemlParam);
                std::string sev;
                {
                    std::lock_guard<std::recursive_mutex> lk(g_mtx);
                    if (g_sess && fi >= 0 && fi < static_cast<int>(g_sess->findings().size()))
                        sev = g_sess->findings()[fi].severity;
                }
                if (sev == "high") cd->clrTextBk = RGB(255, 241, 242);
                else if (sev == "medium") cd->clrTextBk = RGB(255, 251, 235);
                cd->clrText = RGB(30, 41, 59);
                return CDRF_NEWFONT | CDRF_NOTIFYPOSTPAINT;
            }
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPOSTPAINT) {
                int fi = static_cast<int>(cd->nmcd.lItemlParam);
                std::string sev;
                {
                    std::lock_guard<std::recursive_mutex> lk(g_mtx);
                    if (g_sess && fi >= 0 && fi < static_cast<int>(g_sess->findings().size()))
                        sev = g_sess->findings()[fi].severity;
                }
                COLORREF bar = COL_INFO;
                if (sev == "high") bar = COL_HIGH;
                else if (sev == "medium") bar = COL_MED;
                else if (sev == "low") bar = COL_LOW;
                RECT r = cd->nmcd.rc;
                r.right = r.left + 4;
                HBRUSH br = CreateSolidBrush(bar);
                FillRect(cd->nmcd.hdc, &r, br);
                DeleteObject(br);
                return CDRF_DODEFAULT;
            }
        }
        return 0;
    }
    case WM_TIMER:
        if (wp == 999) { PostQuitMessage(0); return 0; }
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

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(COL_BG);
    wc.lpszClassName = L"CTFIR_GUI_MAIN";
    if (!RegisterClassW(&wc)) return 10;

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"ctfir — 只读应急工作台",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                1024, 720, nullptr, nullptr, hInst, nullptr);
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
