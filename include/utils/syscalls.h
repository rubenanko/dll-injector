/*
 * syscalls.h — Dynamic SSN Resolution via EAT Sorting
 *
 * Instead of hardcoding syscall numbers (which change across Windows versions),
 * this module resolves them at runtime by sorting ntdll's Zw* exports by address.
 * The sorted index of each Zw function equals its syscall number.
 *
 * Usage:
 *   1. Call InitSyscalls() once at startup (after PEB lookup is available).
 *   2. Use GetSSN_Hashed(hash) to retrieve the SSN for any Nt* function.
 *   3. The d* wrapper functions handle SetSSN + RunSyscall transparently.
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "utils/peb-lookup.h"
#include "utils/direct-syscalls.h"

/* ============================================================================
 * NTDLL Module Hash
 * ========================================================================= */

#define HASH_NTDLL_DLL  0x145370BBU  /* FNV-1a("NTDLL.DLL") uppercase */

/* ============================================================================
 * Nt Function Hashes (case-sensitive FNV-1a of exact export name)
 * ========================================================================= */

#define HASH_NtAllocateVirtualMemory   0xCA67B978U
#define HASH_NtWriteVirtualMemory      0x43E32F32U
#define HASH_NtReadVirtualMemory       0x6E2A0391U
#define HASH_NtProtectVirtualMemory    0xBD799926U
#define HASH_NtOpenProcess             0x5EA49A38U
#define HASH_NtCreateThreadEx          0xED0594DAU

/* ============================================================================
 * ASM Stub Imports (defined in syscall-stub.nasm)
 * ========================================================================= */

extern void  SetSSN(DWORD ssn);
extern void* RunSyscall;  /* called via cast — address of the stub */

/* ============================================================================
 * Syscall Infrastructure
 * ========================================================================= */

/* Maximum number of Zw* exports we expect in ntdll */
#define MAX_SYSCALL_ENTRIES 600

typedef struct _SYSCALL_ENTRY {
    DWORD  hash;     /* FNV-1a hash of the Nt* name (Zw prefix replaced) */
    PVOID  address;  /* Address of the Zw* export in ntdll */
    DWORD  ssn;      /* Resolved syscall number (filled after sorting) */
} SYSCALL_ENTRY;

/*
 * InitSyscalls — Populate the syscall table by enumerating ntdll's Zw* exports,
 * sorting them by address, and assigning SSNs based on sorted order.
 * Returns true on success.
 */
bool InitSyscalls(void);

/*
 * GetSSN_Hashed — Look up the SSN for an Nt* function by its FNV-1a hash.
 * Returns the SSN, or (DWORD)-1 if not found.
 */
DWORD GetSSN_Hashed(DWORD functionHash);

#endif /* SYSCALLS_H */
