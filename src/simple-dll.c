// x86_64-w64-mingw32-gcc -shared -O2 -o injected-dll.dll simple-dll.c -I. -Wl,--out-implib,libsimple.a -Wl,--output-def,simple.def -luser32 -lshell32 -lgdi32
#include <dll-injector/simple-dll.h>

int g_sleepTime = SLEEPTIME;
int* g_sleepTime_addr = (PVOID)&g_sleepTime;
static LONG g_notify_started = 0;

/**
 * @brief Thread de notification : délègue l'exécution à Notify puis se termine.
 *
 * @param param Paramètre transmis à Notify (non utilisé).
 * @return 0 à la fin de l'exécution.
 */
static DWORD WINAPI NotifyThread(LPVOID param) {
    Notify(param);
    return 0;
}

/**
 * @brief Démarre le thread de notification une seule fois, de manière atomique.
 *
 * Utilise un échange atomique pour garantir qu'un seul thread est créé,
 * même en cas d'appels concurrents.
 *
 * @return Aucun.
 */
static void StartNotifyOnce(void) {
    if (InterlockedCompareExchange(&g_notify_started, 1, 0) != 0) {
        return;
    }

    HANDLE thread = CreateThread(NULL, 0, NotifyThread, NULL, 0, NULL);
    if (thread) {
        CloseHandle(thread);
    }
}

/**
 * @brief Affiche une icône de notification dans la barre des tâches et la met
 *        à jour périodiquement avec l'heure locale et le PID du processus.
 *
 * Boucle indéfiniment en alternant entre deux icônes système et en rafraîchissant
 * le tooltip à intervalle de g_sleepTime millisecondes.
 *
 * @param param Paramètre non utilisé.
 * @return 1 si le temps de veille a été altéré ; ne retourne pas en fonctionnement normal.
 */
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

/**
 * @brief Point d'entrée rundll32 déclenchant la notification système.
 *
 * @param hwnd Handle de fenêtre (non utilisé).
 * @param hinst Handle d'instance (non utilisé).
 * @param lpszCmdLine Ligne de commande (non utilisée).
 * @param nCmdShow Mode d'affichage (non utilisé).
 * @return Aucun.
 */
EXPORT void CALLBACK notifyentry(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    (void)hwnd;
    (void)hinst;
    (void)lpszCmdLine;
    (void)nCmdShow;
    StartNotifyOnce();
}

/**
 * @brief Fonction de test exportée : déclenche la notification et affiche une boîte de dialogue.
 *
 * @param hwnd Handle de la fenêtre parente pour la boîte de dialogue.
 * @param hinst Handle d'instance (non utilisé).
 * @param lpszCmdLine Ligne de commande (non utilisée).
 * @param nCmdShow Mode d'affichage (non utilisé).
 * @return Aucun.
 */
EXPORT void CALLBACK TestFunction(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    (void)hinst;
    (void)lpszCmdLine;
    (void)nCmdShow;
    StartNotifyOnce();
    MessageBoxW(hwnd, L"TestFunction() called!", L"TestFunction", MB_OK | MB_ICONINFORMATION);
    Sleep(10000);
}

/**
 * @brief Point d'entrée principal de la DLL.
 *
 * Déclenche la notification au premier attachement au processus.
 *
 * @param hinstDLL Handle de l'instance de la DLL (non utilisé).
 * @param fdwReason Raison de l'appel (DLL_PROCESS_ATTACH, etc.).
 * @param lpvReserved Réservé (non utilisé).
 * @return TRUE systématiquement.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        StartNotifyOnce();
    }
    return TRUE;
}
