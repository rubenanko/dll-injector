#ifndef DLL_INJECTOR_H
#define DLL_INJECTOR_H

#include <windows.h>

DWORD ProcessWalking(char* exeFileName);
HANDLE injectDllPath(DWORD dwProcessId, const char* dllPath, LPVOID* remoteBuffer);
HANDLE startDllSubProcess(HANDLE hProcess, LPVOID remoteBuffer);

#endif // !DLL_INJECTOR_H
