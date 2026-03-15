# Payload Runner — FUD DLL Injector

Injecteur de DLL par **manual mapping** ciblant Windows x64, développé dans un cadre académique Red Team. L'objectif est d'injecter une DLL arbitraire dans un processus cible sans passer par `LoadLibrary`, tout en évitant la détection par les solutions AV/EDR courantes.

---

## Techniques mises en œuvre

| Technique | Description |
|---|---|
| **Manual Mapping** | Copie manuelle du PE en mémoire distante, sans `LoadLibrary` |
| **API Hashing (FNV-1a)** | Résolution des API Win32 au runtime via parcours du PEB — aucun import suspect dans l'IAT |
| **ASM stub PIC** | Shellcode x64 position-independent : parcours du PEB dans le processus cible pour résoudre `LoadLibraryA` et `GetProcAddress` |
| **C Loader stub PIC** | Stub compilé sans CRT : relocation de base, résolution de l'IAT, appel du `DllMain` |

---

## Architecture

```
Injecteur (host)                     Processus cible (Notepad.exe)
─────────────────────────────────    ──────────────────────────────────────
1. PEB walk → résolution des API
2. Validation PE (MZ + NT + PE32+)
3. VirtualAllocEx + WriteProcess-    ← [DLL headers + sections]
   Memory                            ← [ASM stub | C stub | MANUAL_MAPPING_DATA]
4. CreateRemoteThread ──────────────→ ASM stub
                                          │ PEB walk → LoadLibraryA, GetProcAddress
                                          └→ C_LoaderStub(pData)
                                               ├ Relocations (delta patch)
                                               ├ Résolution IAT
                                               └ DllMain(DLL_PROCESS_ATTACH)
```

---

## Structure du projet

```
.
├── src/
│   ├── main.c              # Point d'entrée : init API, process walking, injection
│   ├── dll-injector.c      # Orchestration : manual mapping + injection des stubs
│   ├── pe-parser.c         # Validation et lecture du fichier PE
│   ├── loader-stub.c       # Stub C PIC (reloc + IAT + DllMain)
│   ├── asm-stub.nasm       # Stub ASM PIC (PEB walk dans le processus cible)
│   ├── simple-dll.c        # DLL de démonstration (notification systray)
│   └── utils/              # Résolution API (PEB/FNV-1a), sécurité stdio
├── include/
│   ├── dll-injector/       # En-têtes principaux
│   ├── utils/              # PEB lookup, macros, log
│   └── windows/            # Structures PE custom
├── docs/                   # Doxyfile + thème doxygen-awesome-css
├── test/                   # Tests unitaires (PE parser)
├── Makefile
└── deploy.sh               # Build + copie vers le partage Windows
```

---

## Prérequis

- `x86_64-w64-mingw32-gcc` — cross-compilateur Linux → Windows
- `nasm` — assembleur pour le stub ASM
- `doxygen` — génération de la documentation (optionnel)

---

## Build

```bash
# Build release (défaut)
make

# Build debug
make MODE=debug

# Build + déploiement vers ~/windows_share
./deploy.sh

# Documentation
make docs        # génère docs/html/
make clean-docs  # supprime docs/html/ et docs/latex/
```

Les artefacts sont produits dans `build/` :

| Fichier | Description |
|---|---|
| `dll-injector.exe` | L'injecteur |
| `injected-dll.dll` | La DLL de démonstration |

---

## Utilisation

```cmd
dll-injector.exe <chemin_vers_la_dll>
```

Le processus cible est **Notepad.exe** (codé en dur à titre de démonstration). L'injecteur localise le premier processus correspondant, mappe la DLL par manual mapping et exécute le loader via un thread distant.

---

## Avertissement

Ce projet est développé dans un cadre **académique et pédagogique**. L'utilisation de ces techniques sur des systèmes sans autorisation explicite est illégale.
