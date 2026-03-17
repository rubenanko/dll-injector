#include <dll-injector/dll-injector.h>
#include <dll-injector/loader-stub.h>
#include <utils/peb-lookup.h>
#include <utils/memory.h>
#include <asm-stub-bin.h>

/**
 * @brief retourne vrai si les chaines sont égales faux sinon
 *        
 *
 * @param str1 chaine 1
 * @param str2 chaine 2
 * @return str1 == str2
 */

int equalStrings(char * str1, char * str2)
{
  while(*str1)
  {
    if(*str1++ != *str2++)
      return 0;
  }

  return (*str2 == 0);
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
  hProcessSnap = mem_create_snapshot(TH32CS_SNAPPROCESS, 0);
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    return( FALSE );
  }

  pe32.dwSize = sizeof( PROCESSENTRY32 );

  if( !mem_process32_first( hProcessSnap, &pe32 ) )
  {
    mem_close_handle( hProcessSnap );
    return( FALSE );
  }

  /* Itération sur les entrées du snapshot jusqu'à correspondance du nom. */
  do
  {
    if(equalStrings(pe32.szExeFile, exeFileName)){
      mem_close_handle( hProcessSnap );
      return pe32.th32ProcessID;
    }
  } while(mem_process32_next( hProcessSnap, &pe32 ));

  mem_close_handle( hProcessSnap );
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
  LPVOID pRemoteBuffer;
  int numberOfSections;
  IMAGE_SECTION_HEADER* sectionHeaders;

  dosHeader = (IMAGE_DOS_HEADER*)pe->RawData;
  ntHeaders = (IMAGE_NT_HEADERS*)(pe->RawData + dosHeader->e_lfanew);

  /* Allocation de la mémoire distante pour l'image complète de la DLL. */
  pRemoteBuffer = mem_virtual_alloc_ex(
    hProcess,
    NULL,
    ntHeaders->OptionalHeader.SizeOfImage,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
  );
  if(pRemoteBuffer == NULL){
    return NULL;
  }

  /* Écriture des en-têtes PE dans le tampon distant. */
  mem_write_process_memory(hProcess, pRemoteBuffer, pe->RawData,
                           ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

  numberOfSections = ntHeaders->FileHeader.NumberOfSections;
  sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

  /* Écriture de chaque section à son adresse virtuelle respective. */
  for(int i = 0; i < numberOfSections; i++){
    mem_write_process_memory(
      hProcess,
      (LPVOID)((DWORD_PTR)pRemoteBuffer + sectionHeaders[i].VirtualAddress),
      pe->RawData + sectionHeaders[i].PointerToRawData,
      sectionHeaders[i].SizeOfRawData,
      NULL
    );
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
 * @param pe_raw_data Bytecode de la DLL à injecter.
 * @param size_pe_raw_data Taille du bytecode pe_raw_data
 * @param remoteBuffer Pointeur de sortie vers le tampon distant alloué (non utilisé en retour).
 * @return Handle du processus cible en cas de succès, ou NULL en cas d'erreur.
 */
HANDLE injectDll(DWORD dwProcessId, PVOID pe_raw_data, int size_pe_raw_data, LPVOID* remoteBuffer){
  HANDLE hProcess;
  LPVOID pRemoteBuffer;
  MANUAL_MAPPING_DATA data = {0};
  IMAGE_PE_FILE pe = {};

  hProcess = mem_open_process(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

  SetRawDataBis(pe_raw_data, size_pe_raw_data, &pe);

  pRemoteBuffer = MannualMappingDll(hProcess, &pe);
  if(pRemoteBuffer == NULL){
    mem_close_handle(hProcess);
    return NULL;
  }

  data.pBaseAddress = pRemoteBuffer;

  data.pLoadLibraryA   = NULL; /* Résolu par le stub ASM dans le processus cible. */
  data.pGetProcAddress = NULL; /* Résolu par le stub ASM dans le processus cible. */
  data.pCStubAddress   = NULL; /* Fixé par injectManualMappingStub. */

  /* Le stub ASM est embarqué à la compilation via asm-stub-bin.h (généré par xxd -i). */
  BYTE *asmStubBuffer = build_asm_stub_bin;
  long asmStubSize = (long)build_asm_stub_bin_len;

  /* Calcul de la taille du stub C compilé en PIC. */
  DWORD cStubSize = (DWORD)((BYTE *)C_LoaderStub_End - (BYTE *)C_LoaderStub);

  HANDLE hThread = injectManualMappingStub(
      hProcess, &data,
      asmStubBuffer, (DWORD)asmStubSize,
      (LPVOID)C_LoaderStub, cStubSize);

  if (hThread == NULL) {
    mem_close_handle(hProcess);
    return NULL;
  }

  mem_close_handle(hThread);
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
    LPVOID pRemoteMem = NULL;
    LPVOID pRemoteAsmStub = NULL;
    LPVOID pRemoteCStub = NULL;
    LPVOID pRemoteData = NULL;
    HANDLE hThread = NULL;
    SIZE_T totalSize = asmStubSize + cStubSize + sizeof(MANUAL_MAPPING_DATA);

    /* Allocation d'un bloc contigu : stub ASM | stub C | MANUAL_MAPPING_DATA. */
    pRemoteMem = mem_virtual_alloc_ex(hProcess, NULL, totalSize,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (pRemoteMem == NULL) {
        return NULL;
    }

    pRemoteAsmStub = pRemoteMem;
    pRemoteCStub = (LPVOID)((BYTE*)pRemoteAsmStub + asmStubSize);
    pRemoteData = (LPVOID)((BYTE*)pRemoteCStub + cStubSize);

    /* Mise à jour de l'adresse distante du stub C dans la structure de données. */
    pData->pCStubAddress = pRemoteCStub;

    if (!mem_write_process_memory(hProcess, pRemoteAsmStub, pAsmStub, asmStubSize, NULL)) {
        goto cleanup;
    }

    if (!mem_write_process_memory(hProcess, pRemoteCStub, pCStub, cStubSize, NULL)) {
        goto cleanup;
    }

    if (!mem_write_process_memory(hProcess, pRemoteData, pData, sizeof(MANUAL_MAPPING_DATA), NULL)) {
        goto cleanup;
    }

    /* Création du thread distant — point d'entrée : stub ASM, argument : pRemoteData. */
    hThread = mem_create_remote_thread(hProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)pRemoteAsmStub,
                                       pRemoteData, 0, NULL);
    if (hThread == NULL) {
        goto cleanup;
    }

    return hThread;

cleanup:
    if (pRemoteMem) mem_virtual_free_ex(hProcess, pRemoteMem, 0, MEM_RELEASE);
    return NULL;
}
