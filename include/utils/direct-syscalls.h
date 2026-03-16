#ifndef DIRECT_SYSCALLS_H
#define DIRECT_SYSCALLS_H

#include <windows.h>
#include <ntdef.h>

typedef LONG NTSTATUS;
typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

#ifndef _WINTERNL_

typedef struct _CLIENT_ID {
   HANDLE UniqueProcess;
   HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p,n,a,r,s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

NTSTATUS dCreateThreadEx(
    PHANDLE ThreadHandle, //out
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

NTSTATUS dAllocateVirtualMemory(
    HANDLE    ProcessHandle, 
    PVOID     *BaseAddress, //out
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize, //out
    ULONG     AllocationType,
    ULONG     Protect
);

NTSTATUS dProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress, //in, out
    PSIZE_T RegionSize, //in, out
    ULONG NewProtection,
    PULONG OldProtection //out
);

NTSTATUS dReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer, //out
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead //out
    );

NTSTATUS dWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten //out
);

NTSTATUS dOpenProcess(
    PHANDLE            ProcessHandle, //out
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);
#endif
