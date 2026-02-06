#include "../include/dll-injector/dll-injector.h"
#include <string.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>

static void printError(const TCHAR* msg){
  DWORD errCode;
  TCHAR buffer[512];

  errCode = GetLastError();
  FormatMessage(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    errCode,
    0,
    buffer,
    (DWORD)(sizeof(buffer) / sizeof(TCHAR)),
    NULL
  );
  _ftprintf(stderr, TEXT("%s failed with error %lu: %s\n"), msg, errCode, buffer);
}

/* DLL Injector
* Goal : Start a DLL function as module of a targetted process.
* Steps :
* - Process Walking : 
*   - Snapshot : CreateToolhelp32Snapshot
*   - Walk : Process32First/Next -> LPPROCESSENTRY32
*     - Compare name  of the executable file for the process : szExeFile
*   - Get th32ProcessID
* - OpenProcess sur le PID visé
* - VirtualAllowEx pour la chaîne du chemin
* - WriteProcessMemory pour copier le chemin
* - Récupérer l'adresse de LoadLibraryA dans kernel32.dll
* - CreateRemoteThread(..., addressOfLoadLin, addressOfString,...)
*/

DWORD ProcessWalking(char* exeFileName){
  HANDLE hProcessSnap;
  PROCESSENTRY32 pe32;

  // Take a snapshot of all processes in the system
  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    printError( TEXT("CreateToolhelp32Snapshot (of processes)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( PROCESSENTRY32 );

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    printError( TEXT("Process32First") ); // show cause of failure
    CloseHandle( hProcessSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the snapshot of processes, and
  // return th32ProcessID of the process associated to exeFileName 
  do
  { 
    if(strcmp(pe32.szExeFile, exeFileName) == 0){
      CloseHandle( hProcessSnap );
      return pe32.th32ProcessID;
    } 
  } while(Process32Next( hProcessSnap, &pe32 ));
  
  CloseHandle( hProcessSnap );
  return 0;
}

// 
// - OpenProcess sur le PID visé
// - VirtualAllowEx pour la chaîne du chemin
// - WriteProcessMemory pour copier le chemin

HANDLE injectDllPath(DWORD dwProcessId, const char* dllPath, LPVOID* remoteBuffer){
  HANDLE hProcess;
  LPVOID pRemoteBuffer;
  SIZE_T pathSize;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
  if(hProcess == NULL){
    return NULL;
  }

  pathSize = strlen(dllPath) + 1;
  pRemoteBuffer = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if(pRemoteBuffer == NULL){
    CloseHandle(hProcess);
    return NULL;
  }

  if(!WriteProcessMemory(hProcess, pRemoteBuffer, dllPath, pathSize, NULL)){
    VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return NULL;
  }

  if(remoteBuffer != NULL){
    *remoteBuffer = pRemoteBuffer;
  }

  /* Caller owns hProcess and remote buffer, and should CloseHandle/VirtualFreeEx. */
  return hProcess;
}

/* startDllSubProcess
 * IN: 
 */
HANDLE startDllSubProcess(HANDLE hProcess, LPVOID remoteBuffer){
  HMODULE hKernel32;
  FARPROC pLoadLibraryA;
  HANDLE hThread;

  hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
  if(hKernel32 == NULL){
    return NULL;
  }

  pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
  if(pLoadLibraryA == NULL){
    return NULL;
  }

  hThread = CreateRemoteThread(
    hProcess,
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)pLoadLibraryA,
    remoteBuffer,
    0,
    NULL
  );
  if(hThread == NULL){
    return NULL;
  }

  WaitForSingleObject(hThread, INFINITE);
  /* Caller should CloseHandle(hThread) after use. */
  return hThread;
}
