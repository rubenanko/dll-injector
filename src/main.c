#include <dll-injector/main.h>
#include "utils/peb-lookup.h"

/* Main entry:
 * - Initializes dynamic API resolution (PEB walk)
 * - Finds notepad.exe if present
 * - Injects DLL path provided as argv[1]
 */
int main(int argc, char** argv){
  DWORD targetPid;
  HANDLE hProcess;
  LPVOID remoteBuffer;

  /* Initialize all dynamically resolved APIs before any injection work.
   * This must be the very first operation — no Windows API calls before this. */
  if(!InitDynamicAPIs()){
    printf("Failed to initialize dynamic APIs via PEB walk.\n");
    return 1;
  }

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

  g_Api.pCloseHandle(hProcess);
  return 0;
}
