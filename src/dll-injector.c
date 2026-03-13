#include "dll-injector/dll-injector.h"

static void printError(const TCHAR* msg){
  DWORD errCode;
  TCHAR buffer[512];

  errCode = GetLastError();
  FormatMessage(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    errCode,
    0,
    buffer,
    (DWORD)(sizeof(buffer) / sizeof(TCHAR)),
    NULL
  );
  _ftprintf(stderr, TEXT("%s failed with error %lu: %s\n"), msg, errCode, buffer);
}

/* DLL Injector
* Goal : Start a DLL function as module of a targetted process.
* Steps :
* - Process Walking : 
*   - Snapshot : CreateToolhelp32Snapshot
*   - Walk : Process32First/Next -> LPPROCESSENTRY32
*     - Compare name  of the executable file for the process : szExeFile
*   - Get th32ProcessID
* - OpenProcess sur le PID visé
* - Allouer l'espace mémoire virtuel pour la DLL
* - Mapper la DLL dans l'espace mémoire du processus cible
* - Exécuter le stub
* */

DWORD ProcessWalking(char* exeFileName){
  HANDLE hProcessSnap;
  PROCESSENTRY32 pe32;

  // Take a snapshot of all processes in the system
  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    printError( TEXT("CreateToolhelp32Snapshot (of processes)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( PROCESSENTRY32 );

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    printError( TEXT("Process32First") ); // show cause of failure
    CloseHandle( hProcessSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the snapshot of processes, and
  // return th32ProcessID of the process associated to exeFileName 
  do
  { 
    if(strcmp(pe32.szExeFile, exeFileName) == 0){
      CloseHandle( hProcessSnap );
      return pe32.th32ProcessID;
    } 
  } while(Process32Next( hProcessSnap, &pe32 ));
  
  CloseHandle( hProcessSnap );
  return 0;
}

LPVOID MannualMappingDll(HANDLE hProcess, PIMAGE_PE_FILE pe){
  IMAGE_DOS_HEADER* dosHeader;
  IMAGE_NT_HEADERS* ntHeaders;
  LPVOID pRemoteBuffer;
  int numberOfSections;
  IMAGE_SECTION_HEADER* sectionHeaders;

  // 0. Parse the PE file to get the necessary information for mapping
  dosHeader = (IMAGE_DOS_HEADER*)pe->RawData;
  ntHeaders = (IMAGE_NT_HEADERS*)(pe->RawData + dosHeader->e_lfanew);
  
  // 1. Allocate memory in the target process for the DLL
  pRemoteBuffer = VirtualAllocEx(
    hProcess,
    NULL,
    ntHeaders->OptionalHeader.SizeOfImage,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
  );
  if(pRemoteBuffer == NULL){
    printError(TEXT("VirtualAllocEx"));
    return NULL;
  }

  // 2. Write the DLL's headers and sections into the allocated memory
  WriteProcessMemory(hProcess, pRemoteBuffer, pe->RawData, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

  numberOfSections = ntHeaders->FileHeader.NumberOfSections;
  sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
  
  for(int i = 0; i < numberOfSections; i++){
    WriteProcessMemory(
      hProcess,
      (LPVOID)((DWORD_PTR)pRemoteBuffer + sectionHeaders[i].VirtualAddress),
      pe->RawData + sectionHeaders[i].PointerToRawData,
      sectionHeaders[i].SizeOfRawData,
      NULL
    );
  }

  return pRemoteBuffer;
}

HANDLE injectDll(DWORD dwProcessId, const char* dllPath, LPVOID* remoteBuffer){
  HANDLE hProcess;
  LPVOID pRemoteBuffer;
  PIMAGE_PE_FILE pe;
  PMANUAL_MAPPING_DATA pData;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

  pe = malloc(sizeof(IMAGE_PE_FILE));
  SetRawData(dllPath, pe);
  
  pRemoteBuffer = MannualMappingDll(hProcess, pe);
  if(pRemoteBuffer == NULL){
    CloseHandle(hProcess);
    return NULL;
  }
  /*
   * On en est là, il faut augmenter la taille de l'espace réserver 
   * pour rajouter le shellcode PIC et le stub C compilé en PIC (C_Loader_stub)
   *
   */

  pData = (PMANUAL_MAPPING_DATA)malloc(sizeof(MANUAL_MAPPING_DATA));
  pData->pBaseAddress = pRemoteBuffer;

  return hProcess;
}

/* startDllSubProcess
 * IN: 
 */
HANDLE startDllSubProcess(HANDLE hProcess, LPVOID remoteBuffer){
  HMODULE hKernel32;
  FARPROC pLoadLibraryA;
  HANDLE hThread;

  hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
  if(hKernel32 == NULL){
    return NULL;
  }

  pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
  if(pLoadLibraryA == NULL){
    return NULL;
  }

  hThread = CreateRemoteThread(
    hProcess,
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)pLoadLibraryA,
    remoteBuffer,
    0,
    NULL
  );
  if(hThread == NULL){
    return NULL;
  }

  WaitForSingleObject(hThread, INFINITE);
  /* Caller should CloseHandle(hThread) after use. */
  return hThread;
}
