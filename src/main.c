#include "dll-injector.h"
#include <stdio.h>

/* Main entry:
 * - Finds notepad.exe if present
 * - Injects DLL path provided as argv[1]
 */
int main(int argc, char** argv){
  DWORD targetPid;
  HANDLE hProcess;
  HANDLE hThread;
  LPVOID remoteBuffer;

  if(argc < 2){
    printf("Usage: %s <dll_path>\\n", argv[0]);
    return 1;
  }

  targetPid = ProcessWalking("Notepad.exe");
  if(targetPid == 0){
    printf("Target notepad.exe not found.\\n");
    return 1;
  }

  remoteBuffer = NULL;
  hProcess = injectDllPath(targetPid, argv[1], &remoteBuffer);
  if(hProcess == NULL || remoteBuffer == NULL){
    printf("Failed to inject DLL path.\\n");
    return 1;
  }

  hThread = startDllSubProcess(hProcess, remoteBuffer);
  if(hThread == NULL){
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    printf("Failed to start remote thread.\\n");
    return 1;
  }

  CloseHandle(hThread);
  VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
  CloseHandle(hProcess);
  return 0;
}
