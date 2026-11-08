// ctfir PoC GUI — M0 兼容探针：Win32 原生窗口 + 消息泵
// --selftest --out <path>：建窗、泵消息 1.5 秒后自退，写结果文件（供 ssh 冒烟）
// 验证：Win7 SP1 API 面、中文标题/绘制、/MT 静态 CRT 下 GUI 子系统可启动
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
                  L"CTF 只读应急助手 PoC\nWin32 原生 / 静态CRT / 目标 Win7 SP1+",
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
            if (lstrcmpiW(argv[i], L"--selftest") == 0) {
                selftest = TRUE;
            } else if (lstrcmpiW(argv[i], L"--out") == 0 && i + 1 < argc) {
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
    wc.lpszClassName = L"CTFIR_POC_WND";
    if (!RegisterClassW(&wc)) return 10;

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"ctfir PoC",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                640, 420, NULL, NULL, hInst, NULL);
    if (!hwnd) return 11;
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    // 泵消息 1.5 秒（MVP 真实窗口循环冒烟；非交互环境同样有效）
    DWORD start = GetTickCount();
    MSG msg;
    BOOL quit = FALSE;
    while (!quit && GetTickCount() - start < 1500) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { quit = TRUE; break; }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (!quit) Sleep(10);
    }
    DestroyWindow(hwnd);

    if (selftest && outPath[0]) {
        FILE* f = _wfopen(outPath, L"w");
        if (f) {
            fprintf(f, "ctfir-gui-selftest OK build=M0 window_created=1 "
                       "message_pumped=1500ms\n");
            fclose(f);
        }
    }
    return 0;
}
