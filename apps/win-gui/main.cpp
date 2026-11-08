// ctfir-gui — Win32 原生 GUI（WP5 完整化；当前为可构建的窗口骨架 + 自检模式）
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        DrawTextW(dc,
                  L"ctfir — CTF 只读应急助手\n"
                  L"（界面开发中：WP5 将提供模块列表/结果/证据/建议/取消）",
                  -1, &rc, DT_CENTER | DT_VCENTER | DT_WORDBREAK);
        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    BOOL selftest = FALSE;
    wchar_t outPath[MAX_PATH] = L"";
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (lstrcmpiW(argv[i], L"--selftest") == 0) selftest = TRUE;
            else if (lstrcmpiW(argv[i], L"--out") == 0 && i + 1 < argc) {
                lstrcpynW(outPath, argv[i + 1], MAX_PATH);
                ++i;
            }
        }
        LocalFree(argv);
    }

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"CTFIR_GUI_WND";
    if (!RegisterClassW(&wc)) return 10;

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"ctfir — CTF 只读应急助手",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                760, 520, NULL, NULL, hInst, NULL);
    if (!hwnd) return 11;
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    DWORD start = GetTickCount();
    MSG msg;
    BOOL quit = FALSE;
    while (!quit) {
        BOOL have = GetMessageW(&msg, NULL, 0, 0);
        if (have <= 0) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        // selftest：1.5 秒后自退
        if (selftest && GetTickCount() - start > 1500) break;
        (void)quit;
    }
    DestroyWindow(hwnd);

    if (selftest && outPath[0]) {
        FILE* f = _wfopen(outPath, L"w");
        if (f) {
            fprintf(f, "ctfir-gui-selftest OK window_created=1 message_pumped=yes\n");
            fclose(f);
        }
    }
    return 0;
}
