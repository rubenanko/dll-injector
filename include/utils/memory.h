/**
 * @file memory.h
 * @brief Interface unifiée pour les opérations mémoire sur les processus distants.
 *
 * Ce module fournit des wrappers transparents qui utilisent les direct syscalls NT
 * lorsque disponibles, et se rabattent sur g_Api (résolution dynamique via PEB) sinon.
 *
 * Direct syscalls utilisés (src/utils/direct-syscalls.asm) :
 *   - NtOpenProcess           → mem_open_process
 *   - NtAllocateVirtualMemory → mem_virtual_alloc_ex
 *   - NtWriteVirtualMemory    → mem_write_process_memory
 *   - NtReadVirtualMemory     → mem_read_process_memory
 *   - NtProtectVirtualMemory  → mem_virtual_protect_ex
 *   - NtCreateThreadEx        → mem_create_remote_thread
 *
 * Fallback g_Api (pas de direct syscall NT équivalent) :
 *   - VirtualFreeEx, CloseHandle, CreateToolhelp32Snapshot,
 *     Process32First, Process32Next, GetLastError, FormatMessageA
 */

#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>
#include <tlhelp32.h>

/* ============================================================================
 * Manipulation de processus distants — via direct syscalls NT
 * ========================================================================= */

/**
 * @brief Ouvre un handle sur le processus spécifié via NtOpenProcess.
 * @return Handle valide ou NULL en cas d'échec.
 */
HANDLE mem_open_process(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

/**
 * @brief Alloue de la mémoire dans un processus distant via NtAllocateVirtualMemory.
 * @return Adresse de base allouée ou NULL en cas d'échec.
 */
LPVOID mem_virtual_alloc_ex(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                             DWORD flAllocationType, DWORD flProtect);

/**
 * @brief Écrit dans la mémoire d'un processus distant via NtWriteVirtualMemory.
 * @return TRUE en cas de succès.
 */
BOOL mem_write_process_memory(HANDLE hProcess, LPVOID lpBaseAddress,
                               LPCVOID lpBuffer, SIZE_T nSize,
                               SIZE_T *lpNumberOfBytesWritten);

/**
 * @brief Lit la mémoire d'un processus distant via NtReadVirtualMemory.
 * @return TRUE en cas de succès.
 */
BOOL mem_read_process_memory(HANDLE hProcess, LPCVOID lpBaseAddress,
                              LPVOID lpBuffer, SIZE_T nSize,
                              SIZE_T *lpNumberOfBytesRead);

/**
 * @brief Modifie la protection d'une région mémoire distante via NtProtectVirtualMemory.
 * @return TRUE en cas de succès.
 */
BOOL mem_virtual_protect_ex(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                             DWORD flNewProtect, PDWORD lpflOldProtect);

/**
 * @brief Crée un thread dans un processus distant via NtCreateThreadEx.
 * @return Handle du thread créé ou NULL en cas d'échec.
 */
HANDLE mem_create_remote_thread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                 SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
                                 LPVOID lpParameter, DWORD dwCreationFlags,
                                 LPDWORD lpThreadId);

/* ============================================================================
 * Manipulation de processus distants — fallback g_Api
 * ========================================================================= */

/**
 * @brief Libère de la mémoire dans un processus distant. Fallback : g_Api.pVirtualFreeEx.
 */
BOOL mem_virtual_free_ex(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                          DWORD dwFreeType);

/**
 * @brief Ferme un handle. Fallback : g_Api.pCloseHandle.
 */
BOOL mem_close_handle(HANDLE hObject);

/* ============================================================================
 * Énumération des processus — fallback g_Api
 * ========================================================================= */

/**
 * @brief Crée un snapshot système. Fallback : g_Api.pCreateToolhelp32Snapshot.
 */
HANDLE mem_create_snapshot(DWORD dwFlags, DWORD th32ProcessID);

/**
 * @brief Récupère la première entrée de processus du snapshot.
 *        Fallback : g_Api.pProcess32First.
 */
BOOL mem_process32_first(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

/**
 * @brief Récupère l'entrée de processus suivante du snapshot.
 *        Fallback : g_Api.pProcess32Next.
 */
BOOL mem_process32_next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

/* ============================================================================
 * Gestion des erreurs — fallback g_Api
 * ========================================================================= */

/**
 * @brief Retourne le dernier code d'erreur Win32. Fallback : g_Api.pGetLastError.
 */
DWORD mem_get_last_error(void);

/**
 * @brief Formate un message d'erreur système. Fallback : g_Api.pFormatMessageA.
 */
DWORD mem_format_message(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
                          DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize,
                          va_list *Arguments);

#endif /* MEMORY_H */
