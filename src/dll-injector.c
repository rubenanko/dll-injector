#include "dll-injector/dll-injector.h"
#include "dll-injector/loader-stub.h"
#include "utils/peb-lookup.h"
#include "utils/syscalls.h"
#include "asm-stub-bin.h"

#ifdef DEBUG
#include <stdio.h>
#endif

/* ============================================================================
 * Journalisation des erreurs
 * ========================================================================= */

/**
 * @brief Affiche un message d'erreur formaté avec le code Win32 correspondant.
 *
 * Interroge GetLastError() via la table d'API dynamique, puis formate le
 * message système avec FormatMessageA. Utilisé uniquement pour les appels
 * WinAPI (CreateToolhelp32Snapshot, etc.) qui ne retournent pas de NTSTATUS.
 *
 * @param msg Préfixe descriptif de l'opération ayant échoué.
 */
static void printError(const char* msg){
#ifdef DEBUG
  DWORD errCode;
  char  buffer[512];

  errCode = g_Api.pGetLastError();
  g_Api.pFormatMessageA(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, errCode, 0,
    buffer, (DWORD)(sizeof(buffer) / sizeof(char)), NULL
  );
  fprintf(stderr, "[-] %s : erreur %lu : %s\n", msg, errCode, buffer);
#else
  (void)msg;
#endif
}

/* ============================================================================
 * Enumération des processus
 * ========================================================================= */

/**
 * @brief Parcourt la liste des processus actifs et retourne le PID correspondant
 *        au nom d'exécutable spécifié.
 *
 * Utilise CreateToolhelp32Snapshot (résolu dynamiquement via g_Api) pour
 * capturer un instantané des processus, puis itère jusqu'à correspondance.
 *
 * @param exeFileName Nom de l'exécutable cible (ex. : "Notepad.exe").
 * @return PID du processus trouvé, ou 0 si introuvable.
 */
DWORD ProcessWalking(char* exeFileName){
  HANDLE       hProcessSnap;
  PROCESSENTRY32 pe32;

  hProcessSnap = g_Api.pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(hProcessSnap == INVALID_HANDLE_VALUE){
    printError("CreateToolhelp32Snapshot");
    return 0;
  }

  pe32.dwSize = sizeof(PROCESSENTRY32);

  if(!g_Api.pProcess32First(hProcessSnap, &pe32)){
    printError("Process32First");
    g_Api.pCloseHandle(hProcessSnap);
    return 0;
  }

  /* Itération sur les entrées du snapshot jusqu'à correspondance du nom. */
  do {
    if(strcmp(pe32.szExeFile, exeFileName) == 0){
      g_Api.pCloseHandle(hProcessSnap);
      return pe32.th32ProcessID;
    }
  } while(g_Api.pProcess32Next(hProcessSnap, &pe32));

  g_Api.pCloseHandle(hProcessSnap);
  return 0;
}

/* ============================================================================
 * Mapping manuel de la DLL
 * ========================================================================= */

/**
 * @brief Mappe manuellement une DLL dans l'espace mémoire d'un processus cible.
 *
 * Alloue via NtAllocateVirtualMemory un bloc de la taille de SizeOfImage, puis
 * y écrit les en-têtes PE et chacune des sections au décalage correspondant à
 * leur adresse virtuelle relative (VirtualAddress).
 *
 * @param hProcess Handle du processus cible (PROCESS_ALL_ACCESS).
 * @param pe       Pointeur vers la structure IMAGE_PE_FILE contenant les données brutes.
 * @return Adresse de base du tampon distant, ou NULL en cas d'erreur.
 */
LPVOID MannualMappingDll(HANDLE hProcess, PIMAGE_PE_FILE pe){
  IMAGE_DOS_HEADER*    dosHeader;
  IMAGE_NT_HEADERS*    ntHeaders;
  IMAGE_SECTION_HEADER* sectionHeaders;
  PVOID   pRemoteBuffer = NULL;
  int     numberOfSections;
  SIZE_T  regionSize;
  SIZE_T  bytesWritten;
  NTSTATUS status;

  dosHeader = (IMAGE_DOS_HEADER*)pe->RawData;
  ntHeaders = (IMAGE_NT_HEADERS*)(pe->RawData + dosHeader->e_lfanew);

  /* Allocation distante pour l'image entière.
   * pRemoteBuffer vaut NULL : le noyau choisit librement l'adresse de base. */
  regionSize = (SIZE_T)ntHeaders->OptionalHeader.SizeOfImage;
  status = dAllocateVirtualMemory(
    hProcess, &pRemoteBuffer, 0, &regionSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
  );
  if(status != 0){
#ifdef DEBUG
    fprintf(stderr, "[-] dAllocateVirtualMemory (image DLL) : NTSTATUS 0x%08lX\n", (unsigned long)status);
#endif
    return NULL;
  }
#ifdef DEBUG
  printf("[+] dAllocateVirtualMemory (image DLL) : base %p, taille %llu\n",
         pRemoteBuffer, (unsigned long long)regionSize);
#endif

  /* Écriture des en-têtes PE. */
  bytesWritten = 0;
  status = dWriteVirtualMemory(
    hProcess, pRemoteBuffer, pe->RawData,
    ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten
  );
  if(status != 0){
#ifdef DEBUG
    fprintf(stderr, "[-] dWriteVirtualMemory (en-têtes PE) : NTSTATUS 0x%08lX\n", (unsigned long)status);
#endif
    return NULL;
  }

  numberOfSections = ntHeaders->FileHeader.NumberOfSections;
  sectionHeaders   = IMAGE_FIRST_SECTION(ntHeaders);

  /* Écriture de chaque section à son adresse virtuelle respective. */
  for(int i = 0; i < numberOfSections; i++){
    PVOID sectionDest = (PVOID)((BYTE*)pRemoteBuffer + sectionHeaders[i].VirtualAddress);
    bytesWritten = 0;
    status = dWriteVirtualMemory(
      hProcess, sectionDest,
      pe->RawData + sectionHeaders[i].PointerToRawData,
      sectionHeaders[i].SizeOfRawData, &bytesWritten
    );
    if(status != 0){
#ifdef DEBUG
      fprintf(stderr, "[-] dWriteVirtualMemory (section %d) : NTSTATUS 0x%08lX\n",
              i, (unsigned long)status);
#endif
      return NULL;
    }
#ifdef DEBUG
    printf("[+] Section %d (%.8s) : %llu octets écrits\n",
           i, (char*)sectionHeaders[i].Name, (unsigned long long)bytesWritten);
#endif
  }

  return pRemoteBuffer;
}

/* ============================================================================
 * Orchestration de l'injection
 * ========================================================================= */

/**
 * @brief Orchestre l'injection complète d'une DLL par manual mapping.
 *
 * Ouvre le processus via NtOpenProcess, lit et valide le fichier PE, mappe
 * la DLL en mémoire distante, puis déclenche l'exécution via le stub de
 * chargement.
 *
 * @param dwProcessId Identifiant du processus cible.
 * @param dllPath     Chemin absolu vers le fichier DLL à injecter.
 * @param remoteBuffer Paramètre de sortie réservé (non utilisé en retour).
 * @return Handle du processus cible en cas de succès, NULL sinon.
 */
HANDLE injectDll(DWORD dwProcessId, const char* dllPath, LPVOID* remoteBuffer){
  HANDLE           hProcess    = NULL;
  LPVOID           pRemoteBuffer;
  PIMAGE_PE_FILE   pe;
  PMANUAL_MAPPING_DATA pData;
  NTSTATUS         status;

  /* Ouverture du processus via syscall direct.
   * Les deux structures doivent être mises à zéro avant usage : le noyau
   * valide que les champs réservés sont nuls (STATUS_INVALID_PARAMETER sinon). */
  OBJECT_ATTRIBUTES oa;
  memset(&oa, 0, sizeof(oa));
  oa.Length = sizeof(oa);

  CLIENT_ID cid;
  memset(&cid, 0, sizeof(cid));
  cid.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;

  status = dOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
  if(status != 0){
#ifdef DEBUG
    fprintf(stderr, "[-] dOpenProcess : NTSTATUS 0x%08lX\n", (unsigned long)status);
#endif
    return NULL;
  }
#ifdef DEBUG
  printf("[+] dOpenProcess : handle %p\n", hProcess);
#endif

  pe = malloc(sizeof(IMAGE_PE_FILE));
  SetRawData(dllPath, pe);

  pRemoteBuffer = MannualMappingDll(hProcess, pe);
  if(pRemoteBuffer == NULL){
    g_Api.pCloseHandle(hProcess);
    return NULL;
  }

  pData = (PMANUAL_MAPPING_DATA)malloc(sizeof(MANUAL_MAPPING_DATA));
  pData->pBaseAddress    = pRemoteBuffer;
  pData->pLoadLibraryA   = NULL; /* Résolu par le stub ASM dans le processus cible. */
  pData->pGetProcAddress = NULL; /* Résolu par le stub ASM dans le processus cible. */
  pData->pCStubAddress   = NULL; /* Fixé par injectManualMappingStub.               */

  /* Le stub ASM est embarqué à la compilation via asm-stub-bin.h (xxd -i). */
  BYTE* asmStubBuffer = asm_stub_bin;
  long  asmStubSize   = (long)asm_stub_bin_len;

  /* Taille du stub C compilé en PIC, déduite de la différence des marqueurs. */
  DWORD cStubSize = (DWORD)((BYTE*)C_LoaderStub_End - (BYTE*)C_LoaderStub);

  HANDLE hThread = injectManualMappingStub(
    hProcess, pData,
    asmStubBuffer, (DWORD)asmStubSize,
    (LPVOID)C_LoaderStub, cStubSize
  );

  free(pData);
  free(pe->RawData);
  free(pe);

  if(hThread == NULL){
    g_Api.pCloseHandle(hProcess);
    return NULL;
  }

  g_Api.pCloseHandle(hThread);
  return hProcess;
}

/* ============================================================================
 * Injection des stubs et création du thread distant
 * ========================================================================= */

/**
 * @brief Alloue et écrit les stubs d'injection dans le processus cible, puis
 *        crée un thread distant pour déclencher leur exécution.
 *
 * Le bloc mémoire alloué est organisé de manière contiguë :
 *   [ stub ASM | stub C | MANUAL_MAPPING_DATA ]
 * Le stub ASM constitue le point d'entrée du thread ; il reçoit en argument
 * l'adresse de la structure MANUAL_MAPPING_DATA.
 *
 * @param hProcess     Handle du processus cible.
 * @param pData        Structure de données à transmettre au stub ASM.
 * @param pAsmStub     Pointeur local vers le bytecode du stub ASM.
 * @param asmStubSize  Taille en octets du stub ASM.
 * @param pCStub       Pointeur local vers le bytecode du stub C.
 * @param cStubSize    Taille en octets du stub C.
 * @return Handle du thread distant créé, ou NULL en cas d'erreur.
 */
HANDLE injectManualMappingStub(HANDLE hProcess, PMANUAL_MAPPING_DATA pData,
                               LPVOID pAsmStub, DWORD asmStubSize,
                               LPVOID pCStub,   DWORD cStubSize){
  PVOID   pRemoteMem    = NULL;
  PVOID   pRemoteAsmStub;
  PVOID   pRemoteCStub;
  PVOID   pRemoteData;
  HANDLE  hThread       = NULL;
  SIZE_T  totalSize     = asmStubSize + cStubSize + sizeof(MANUAL_MAPPING_DATA);
  SIZE_T  regionSize    = totalSize;
  SIZE_T  bytesWritten  = 0;
  NTSTATUS status;

  /* Allocation d'un bloc contigu exécutable.
   * pRemoteMem vaut NULL : le noyau choisit librement l'adresse. */
  status = dAllocateVirtualMemory(
    hProcess, &pRemoteMem, 0, &regionSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
  );
  if(status != 0){
#ifdef DEBUG
    fprintf(stderr, "[-] dAllocateVirtualMemory (stubs) : NTSTATUS 0x%08lX\n", (unsigned long)status);
#endif
    return NULL;
  }

  /* Calcul des adresses distantes de chaque composant dans le bloc. */
  pRemoteAsmStub = pRemoteMem;
  pRemoteCStub   = (PVOID)((BYTE*)pRemoteAsmStub + asmStubSize);
  pRemoteData    = (PVOID)((BYTE*)pRemoteCStub   + cStubSize);

#ifdef DEBUG
  printf("[+] Disposition mémoire — ASM : %p  C : %p  Data : %p\n",
         pRemoteAsmStub, pRemoteCStub, pRemoteData);
#endif

  /* Mise à jour de l'adresse distante du stub C dans la structure de données. */
  pData->pCStubAddress = pRemoteCStub;

  bytesWritten = 0;
  status = dWriteVirtualMemory(hProcess, pRemoteAsmStub, pAsmStub, asmStubSize, &bytesWritten);
  if(status != 0){
#ifdef DEBUG
    fprintf(stderr, "[-] dWriteVirtualMemory (stub ASM) : NTSTATUS 0x%08lX\n", (unsigned long)status);
#endif
    goto nettoyage;
  }

  bytesWritten = 0;
  status = dWriteVirtualMemory(hProcess, pRemoteCStub, pCStub, cStubSize, &bytesWritten);
  if(status != 0){
#ifdef DEBUG
    fprintf(stderr, "[-] dWriteVirtualMemory (stub C) : NTSTATUS 0x%08lX\n", (unsigned long)status);
#endif
    goto nettoyage;
  }

  bytesWritten = 0;
  status = dWriteVirtualMemory(hProcess, pRemoteData, pData, sizeof(MANUAL_MAPPING_DATA), &bytesWritten);
  if(status != 0){
#ifdef DEBUG
    fprintf(stderr, "[-] dWriteVirtualMemory (données) : NTSTATUS 0x%08lX\n", (unsigned long)status);
#endif
    goto nettoyage;
  }

  /* Création du thread distant ; point d'entrée : stub ASM, argument : pRemoteData.
   * ObjectAttributes peut être NULL pour NtCreateThreadEx dans ce contexte. */
  status = dCreateThreadEx(
    &hThread, THREAD_ALL_ACCESS, NULL, hProcess,
    pRemoteAsmStub, pRemoteData, 0, 0, 0, 0, NULL
  );
  if(status != 0){
#ifdef DEBUG
    fprintf(stderr, "[-] dCreateThreadEx : NTSTATUS 0x%08lX\n", (unsigned long)status);
#endif
    goto nettoyage;
  }
#ifdef DEBUG
  printf("[+] dCreateThreadEx : handle thread %p\n", hThread);
#endif

  return hThread;

nettoyage:
  if(pRemoteMem) g_Api.pVirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
  return NULL;
}
