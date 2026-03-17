/*
 * peb-lookup.h — Centralized Dynamic API Resolution via PEB Walk + FNV-1a Hashing
 *
 * PURPOSE:
 *   Removes suspicious Windows API imports (OpenProcess, VirtualAllocEx, etc.)
 *   from the Import Address Table (IAT) by resolving them at runtime through
 *   the Process Environment Block (PEB) InMemoryOrderModuleList.
 *
 * ADDING A NEW API (3 steps):
 *   1. Add a typedef for the function pointer (see typedefs below).
 *   2. Add a member to the DYNAMIC_APIS struct.
 *   3. Add one line in InitDynamicAPIs() to resolve it.
 *
 * GENERATING A HASH:
 *   Module hashes use uppercase FNV-1a on the wide DLL name (e.g., "KERNEL32.DLL").
 *   Function hashes use case-sensitive FNV-1a on the exact export name.
 *   Python one-liner:
 *     python3 -c "
 *     def fnv1a(s):
 *         h=2166136261
 *         for c in s: h=((h^ord(c))*16777619)&0xFFFFFFFF
 *         print(hex(h))
 *     fnv1a('OpenProcess')
 *     "
 */

#ifndef PEB_LOOKUP_H
#define PEB_LOOKUP_H

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdbool.h>

// macro to store data into the .text section
#define DOT_TEXT __attribute__((section(".text")))

/* ============================================================================
 * NT Structures for PEB Walking
 *
 * MinGW's <winternl.h> provides incomplete definitions.  We define our own
 * versions that expose the fields needed to walk InMemoryOrderModuleList and
 * read BaseDllName for each loaded module.
 * ========================================================================= */

typedef struct _MY_PEB_LDR_DATA {
    BYTE       Reserved1[8];       /* Length + Initialized               */
    PVOID      Reserved2;          /* SsHandle                           */
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

/* ============================================================================
 * FNV-1a Hash Constants (32-bit)
 * ========================================================================= */

#define FNV1A_OFFSET_BASIS  2166136261U
#define FNV1A_PRIME         16777619U

/* ============================================================================
 * Pre-calculated Module Hashes (uppercase FNV-1a of wide DLL name)
 * ========================================================================= */

#define HASH_KERNEL32_DLL   0x29CDD463U  /* FNV-1a("KERNEL32.DLL") */

/* ============================================================================
 * Pre-calculated Function Hashes (case-sensitive FNV-1a of export name)
 * ========================================================================= */

#define HASH_OpenProcess                0x4105FC56U
#define HASH_VirtualAllocEx             0xAEB6049CU
#define HASH_VirtualProtect             0x820621f3U
#define HASH_WriteProcessMemory         0xC0088EEAU
#define HASH_CreateRemoteThread         0xC398C463U
#define HASH_VirtualFreeEx              0xE93E8317U
#define HASH_CloseHandle                0xFABA0065U
#define HASH_CreateToolhelp32Snapshot   0x185776B5U
#define HASH_Process32First             0x0A4C8C8FU
#define HASH_Process32Next              0x15EEC872U
#define HASH_GetLastError               0x5056DF37U
#define HASH_FormatMessageA             0x3F75A588U
#define HASH_GetStdHandle               0xe3b9876aU
#define HASH_WriteFile                  0x7f07c44aU

/* ============================================================================
 * Hash Functions
 * ========================================================================= */

/* FNV-1a hash of a narrow (ASCII) string — used for export function names. */
DWORD HashStringFNV1a(const char* str);

/* FNV-1a hash of a wide string, converting each character to uppercase —
 * used for module names where casing may vary (e.g., kernel32.dll vs KERNEL32.DLL). */
DWORD HashStringFNV1aW(const wchar_t* str);

/* ============================================================================
 * PEB-based Resolution Functions
 * ========================================================================= */

/* Walk InMemoryOrderModuleList to find a module whose BaseDllName matches
 * the given FNV-1a hash (uppercase comparison). Returns the module base or NULL. */
HMODULE GetModuleBase_Hashed(DWORD moduleHash);

/* Parse the Export Address Table (EAT) of `hMod` to find an export whose
 * name matches the given FNV-1a hash. Returns the function address or NULL. */
FARPROC GetExportAddress_Hashed(HMODULE hMod, DWORD functionHash);

/* ============================================================================
 * Function Pointer Typedefs
 *
 * Each typedef matches the exact signature of the Windows API it replaces.
 * To add a new API, copy the MSDN signature and create a matching typedef.
 * ========================================================================= */

typedef HANDLE (WINAPI *fnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef LPVOID (WINAPI *fnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL   (WINAPI *fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
typedef BOOL   (WINAPI *fnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE (WINAPI *fnCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL   (WINAPI *fnVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL   (WINAPI *fnCloseHandle)(HANDLE hObject);
typedef HANDLE (WINAPI *fnCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL   (WINAPI *fnProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL   (WINAPI *fnProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef DWORD  (WINAPI *fnGetLastError)(void);
typedef DWORD  (WINAPI *fnFormatMessageA)(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list* Arguments);
typedef HANDLE (WINAPI *fnGetStdHandle)(DWORD nStdHandle);
typedef BOOL   (WINAPI *fnWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

/* ============================================================================
 * DYNAMIC_APIS — The Scalable API Structure
 *
 * All dynamically resolved function pointers live here.  Code throughout the
 * injector accesses them via the global `g_Api` instance.
 * ========================================================================= */

typedef struct _DYNAMIC_APIS {
    /* Process manipulation */
    fnOpenProcess               pOpenProcess;
    fnVirtualAllocEx            pVirtualAllocEx;
    fnVirtualProtect            pVirtualProtect;
    fnWriteProcessMemory        pWriteProcessMemory;
    fnCreateRemoteThread        pCreateRemoteThread;
    fnVirtualFreeEx             pVirtualFreeEx;
    fnCloseHandle               pCloseHandle;
    fnGetStdHandle              pGetStdHandle;
    fnWriteFile                 pWriteFile;

    /* Process enumeration */
    fnCreateToolhelp32Snapshot  pCreateToolhelp32Snapshot;
    fnProcess32First            pProcess32First;
    fnProcess32Next             pProcess32Next;

    /* Error reporting */
    fnGetLastError              pGetLastError;
    fnFormatMessageA            pFormatMessageA;
} DYNAMIC_APIS, *PDYNAMIC_APIS;

/* Global instance — defined in peb-lookup.c */
DOT_TEXT extern DYNAMIC_APIS g_Api;

/* Resolve all APIs in g_Api. Call once at program start.
 * Returns true on success, false if any critical API could not be resolved. */
DYNAMIC_APIS * InitDynamicAPIs(void);

#endif /* PEB_LOOKUP_H */
