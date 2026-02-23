#ifndef DLL_INJECTOR_H
#define DLL_INJECTOR_H

#include <windows.h>
#include <string.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>
#include "pe-parser.h"

typedef struct _MANUAL_MAPPING_DATA {
  LPVOID pLoadLibraryA;
  LPVOID pGetProcAddress;
  LPVOID pBaseAddress;
  LPVOID pCStubAddress;
} MANUAL_MAPPING_DATA, *PMANUAL_MAPPING_DATA;

DWORD ProcessWalking(char* exeFileName);
LPVOID MannualMappingDll(HANDLE hProcess, PIMAGE_PE_FILE pe);
HANDLE injectDll(DWORD dwProcessId, const char* dllPath, LPVOID* remoteBuffer);
HANDLE startDllSubProcess(HANDLE hProcess, LPVOID remoteBuffer);

#endif // !DLL_INJECTOR_H
