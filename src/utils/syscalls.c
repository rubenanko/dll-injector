/*
 * syscalls.c — Dynamic SSN Resolution via EAT Sorting + Wrapper Implementations
 *
 * Resolves syscall numbers at runtime by enumerating all Zw* exports from
 * ntdll, sorting them by address, and using the sorted index as the SSN. This
 * works because Windows assigns consecutive syscall numbers to Nt/Zw functions
 * in the order they appear in memory.
 *
 * The d* wrapper functions call SetSSN() then RunSyscall() via the generic
 * ASM stub, keeping each wrapper small and independent of hardcoded SSNs.
 */

#include "utils/syscalls.h"
#include "utils/macros.h"
#include <stdint.h>
#include <stdio.h>

/* ============================================================================
 * Syscall Table
 * ========================================================================= */

static SYSCALL_ENTRY g_SyscallTable[MAX_SYSCALL_ENTRIES];
static DWORD g_SyscallCount = 0;

/* ============================================================================
 * EAT Enumeration + Sorting
 * ========================================================================= */

/*
 * Insertion sort for syscall entries by address — avoids CRT qsort dependency.
 * For ~400-500 entries this is fast enough and keeps us CRT-free.
 */
static void SortSyscallEntries(SYSCALL_ENTRY *entries, DWORD count) {
  for (DWORD i = 1; i < count; i++) {
    SYSCALL_ENTRY key = entries[i];
    DWORD j = i;
    while (j > 0 && entries[j - 1].address > key.address) {
      entries[j] = entries[j - 1];
      j--;
    }
    entries[j] = key;
  }
}

/*
 * HashZwToNt — Given a Zw* export name, compute the FNV-1a hash as if it
 * started with "Nt" instead of "Zw". This lets us look up by Nt* hash.
 *
 * Example: "ZwAllocateVirtualMemory" -> hash("NtAllocateVirtualMemory")
 */
static DWORD HashZwToNt(const char *zwName) {
  DWORD hash = FNV1A_OFFSET_BASIS;

  /* Hash "Nt" prefix instead of "Zw" */
  hash ^= (DWORD)'N';
  hash *= FNV1A_PRIME;
  hash ^= (DWORD)'t';
  hash *= FNV1A_PRIME;

  /* Hash the rest of the name (skip the "Zw" prefix) */
  const char *rest = zwName + 2;
  while (*rest) {
    hash ^= (DWORD)(unsigned char)*rest;
    hash *= FNV1A_PRIME;
    rest++;
  }

  return hash;
}

bool InitSyscalls(void) {
  /* Step 1: Resolve ntdll.dll base via PEB walk */
  HMODULE hNtdll = GetModuleBase_Hashed(HASH_NTDLL_DLL);
  if (hNtdll == NULL)
    return false;

  BYTE *pBase = (BYTE *)hNtdll;

  /* Step 2: Locate the Export Directory */
  IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER *)pBase;
  if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  IMAGE_NT_HEADERS *pNt = (IMAGE_NT_HEADERS *)(pBase + pDos->e_lfanew);
  if (pNt->Signature != IMAGE_NT_SIGNATURE)
    return false;

  IMAGE_DATA_DIRECTORY *pExportDir =
      &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  if (pExportDir->VirtualAddress == 0 || pExportDir->Size == 0)
    return false;

  IMAGE_EXPORT_DIRECTORY *pExports =
      (IMAGE_EXPORT_DIRECTORY *)(pBase + pExportDir->VirtualAddress);

  DWORD *pAddressOfFunctions = (DWORD *)(pBase + pExports->AddressOfFunctions);
  DWORD *pAddressOfNames = (DWORD *)(pBase + pExports->AddressOfNames);
  WORD *pAddressOfNameOrdinals =
      (WORD *)(pBase + pExports->AddressOfNameOrdinals);

  /* Step 3: Enumerate all Zw* exports and store them with their Nt* hash */
  g_SyscallCount = 0;

  for (DWORD i = 0;
       i < pExports->NumberOfNames && g_SyscallCount < MAX_SYSCALL_ENTRIES;
       i++) {
    const char *name = (const char *)(pBase + pAddressOfNames[i]);

    /* We only care about Zw* functions (paired with Nt* syscalls) */
    if (name[0] == 'Z' && name[1] == 'w') {
      WORD ordinal = pAddressOfNameOrdinals[i];
      DWORD funcRva = pAddressOfFunctions[ordinal];

      g_SyscallTable[g_SyscallCount].hash = HashZwToNt(name);
      g_SyscallTable[g_SyscallCount].address = (PVOID)(pBase + funcRva);
      g_SyscallTable[g_SyscallCount].ssn = 0;
      g_SyscallCount++;
    }
  }

  if (g_SyscallCount == 0)
    return false;

  /* Step 4: Sort by address — the sorted index IS the syscall number */
  SortSyscallEntries(g_SyscallTable, g_SyscallCount);

  /* Step 5: Assign SSNs based on sorted position */
  for (DWORD i = 0; i < g_SyscallCount; i++) {
    g_SyscallTable[i].ssn = i;
  }

  return true;
}

DWORD GetSSN_Hashed(DWORD functionHash) {
  for (DWORD i = 0; i < g_SyscallCount; i++) {
    if (g_SyscallTable[i].hash == functionHash){
      return g_SyscallTable[i].ssn;
    }
  }
  return (DWORD)-1;
}

/* ============================================================================
 * Direct Syscall Wrappers
 *
 * Each wrapper: look up SSN -> set it -> invoke the generic ASM stub.
 * The RunSyscall stub preserves all register arguments (RCX, RDX, R8, R9)
 * and stack arguments, so we cast its address to the correct function type.
 * ========================================================================= */

NTSTATUS dAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                ULONG AllocationType, ULONG Protect) {
  SetSSN(GetSSN_Hashed(HASH_NtAllocateVirtualMemory));
  typedef NTSTATUS(NTAPI * fn)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG,
                               ULONG);
  return ((fn)RunSyscall)(ProcessHandle, BaseAddress, ZeroBits, RegionSize,
                          AllocationType, Protect);
}

NTSTATUS dWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                             PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                             PSIZE_T NumberOfBytesWritten) {
  SetSSN(GetSSN_Hashed(HASH_NtWriteVirtualMemory));
  typedef NTSTATUS(NTAPI * fn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
  return ((fn)RunSyscall)(ProcessHandle, BaseAddress, Buffer,
                          NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS dReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                            PVOID Buffer, SIZE_T NumberOfBytesToRead,
                            PSIZE_T NumberOfBytesRead) {
  SetSSN(GetSSN_Hashed(HASH_NtReadVirtualMemory));
  typedef NTSTATUS(NTAPI * fn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
  return ((fn)RunSyscall)(ProcessHandle, BaseAddress, Buffer,
                          NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS dProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                               PSIZE_T RegionSize, ULONG NewProtection,
                               PULONG OldProtection) {
  SetSSN(GetSSN_Hashed(HASH_NtProtectVirtualMemory));
  typedef NTSTATUS(NTAPI * fn)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
  return ((fn)RunSyscall)(ProcessHandle, BaseAddress, RegionSize, NewProtection,
                          OldProtection);
}

NTSTATUS dOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes,
                      PCLIENT_ID ClientId) {
  SetSSN(GetSSN_Hashed(HASH_NtOpenProcess));
  typedef NTSTATUS(NTAPI * fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                               PCLIENT_ID);
  return ((fn)RunSyscall)(ProcessHandle, DesiredAccess, ObjectAttributes,
                          ClientId);
}

NTSTATUS dCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                         POBJECT_ATTRIBUTES ObjectAttributes,
                         HANDLE ProcessHandle, PVOID StartRoutine,
                         PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
                         SIZE_T StackSize, SIZE_T MaximumStackSize,
                         PVOID AttributeList) {
  SetSSN(GetSSN_Hashed(HASH_NtCreateThreadEx));
  typedef NTSTATUS(NTAPI * fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                               PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T,
                               PVOID);
  return ((fn)RunSyscall)(ThreadHandle, DesiredAccess, ObjectAttributes,
                          ProcessHandle, StartRoutine, Argument, CreateFlags,
                          ZeroBits, StackSize, MaximumStackSize, AttributeList);
}
