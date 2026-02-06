#ifndef __DLL_INJECTOR_MEMORY__
#define __DLL_INJECTOR_MEMORY__

#include <windows.h>

HANDLE open_process_from_name(char * processName);

HANDLE open_process_from_handle(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

LPVOID virtual_alloc_ex(
    LPVOID lpAddress, 
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

int write_process_memory(
    HANDLE hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);

int load_library(char * dllPath);

HANDLE create_snapshot();

#endif