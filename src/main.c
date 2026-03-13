#include <dll-injector/main.h>

/* Main entry:
 * - Finds notepad.exe if present
 * - Injects DLL path provided as argv[1]
 */
int main(int argc, char** argv){
  DWORD targetPid;
  HANDLE hProcess;
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
  hProcess = injectDll(targetPid, argv[1], &remoteBuffer);
  if(hProcess == NULL){
    printf("Failed to inject DLL.\\n");
    return 1;
  }

  CloseHandle(hProcess);
  return 0;
}
