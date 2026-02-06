// x86_64-w64-mingw32-gcc -shared -O2 -o injected-dll.dll simple-dll.c -I. -Wl,--out-implib,libsimple.a -Wl,--output-def,simple.def -luser32 -lshell32 -lgdi32
#include "../include/dll-injector/simple-dll.h"

int g_sleepTime = SLEEPTIME;
int* g_sleepTime_addr = (PVOID)&g_sleepTime;
static LONG g_notify_started = 0;


static DWORD WINAPI NotifyThread(LPVOID param) {
    Notify(param);
    return 0;
}

static void StartNotifyOnce(void) {
    if (InterlockedCompareExchange(&g_notify_started, 1, 0) != 0) {
        return;
    }

    HANDLE thread = CreateThread(NULL, 0, NotifyThread, NULL, 0, NULL);
    if (thread) {
        CloseHandle(thread);
    }
}

DWORD WINAPI Notify(LPVOID param) {
    if (*g_sleepTime_addr != SLEEPTIME) return 1;
    (void)param;
 
    NOTIFYICONDATAW nid = {0};
    nid.cbSize = sizeof(nid);
    nid.hWnd   = CreateWindowW(L"Static", L"", 0, 0,0,0,0, HWND_MESSAGE, 0,0,0);
    nid.uID    = 1;
 
    HICON i1 = LoadIconW(NULL, MAKEINTRESOURCEW(IDI_ERROR));
    HICON i2 = LoadIconW(NULL, MAKEINTRESOURCEW(IDI_WARNING));
 
    nid.uFlags   = /*NIF_GUID |*/ NIF_ICON | NIF_TIP | 0x80;//NIF_SHOWTIP
    /* nid.guidItem = kTrayGuid; */
    nid.hIcon    = i1;
    lstrcpyW(nid.szTip, L"MyApp");
    Shell_NotifyIconW(NIM_ADD, &nid);
    nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &nid);
 
    for (int t = 0;; t ^= 1) {
        SYSTEMTIME st; GetLocalTime(&st);
        wsprintfW(nid.szTip,
            L"[%04d-%02d-%02d %02d:%02d:%02d] %s (PID %lu)",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            UTF16(__FILE__), GetCurrentProcessId());
 
        nid.uFlags = NIF_GUID | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        nid.hIcon  = t ? i2 : i1;
        Shell_NotifyIconW(NIM_MODIFY, &nid);
 
        Sleep(*g_sleepTime_addr);
    }
}

// rundll32 wrapper 
EXPORT void CALLBACK notifyentry(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    (void)hwnd;
    (void)hinst;
    (void)lpszCmdLine;
    (void)nCmdShow;
    StartNotifyOnce();
}

EXPORT void CALLBACK TestFunction(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    (void)hinst;
    (void)lpszCmdLine;
    (void)nCmdShow;
    StartNotifyOnce();
    MessageBoxW(hwnd, L"TestFunction() called!", L"TestFunction", MB_OK | MB_ICONINFORMATION);
    Sleep(10000);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        StartNotifyOnce();
    }
    return TRUE;
}
