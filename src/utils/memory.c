#include <utils/memory.h>

HANDLE open_process_from_name(char * processName)
{
    HANDLE hSnapshot = create_snapshot();
    LPPROCESSENTRY32 lppe;

    while(Process32Next(hSnapshot,lppe))
    {
        
    }
    CloseHandle(hSnapshot);
}

HANDLE open_process_from_handle(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId)
{
    return OpenProcess(dwDesiredAccess,bInheritHandle,dwProcessId);
}

LPVOID virtual_alloc_ex(
    LPVOID lpAddress, 
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect)
{
    return VirtualAllocEx(lpAddress,dwSize,flAllocationType,flProtect);
}

int write_process_memory(
    HANDLE hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten)
{
    return (int)WriteProcessMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten);
}

int load_library(char * dllPath);

HANDLE create_snapshot()
{
    return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); // TH32CS_SNAPPROCESS = 0x02, all processes
}

