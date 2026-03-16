# Fully UnDetected (FUD) DLL Injector

- Lien VirusTotal: <LINK>
- Backup Archive.org: <LINK>
- Sha256sum: <SUM>

> [!abstract]
> Injecteur de DLL par **manual mapping** ciblant Windows x64, développé dans un cadre académique Red Team.
> L'objectif est d'injecter une DLL arbitraire dans un processus cible sans passer par l'API de Windows afin d'éviter la détection par les solutions AV/EDR courantes.

_Mots-clés : Mannual Mapping, Dynamic API Resolution, Direct Syscalls, PIC Shellcoding, Remote Process Injection_

## Contexte des missions Red Team

Dans le cadre d'une mission Red Team, disposer d'un injecteur de DLL indétectable est indispensable pour mêner assurer la _persistance_ de l'accès obtenu sur un système et procéder ultérieurement aux différents _pivots_.
En pratique, on injecte un _payload C2_, dît _Command and Control_, afin de réaliser des actions distantes sur la machine infectée depuis un serveur d'attaque.
On donne la représentation schématique suivante d'une telle attaque :

![Schéma d'attaque C2](assets/c2_attack_schema.svg "Schéma d'attaque C2")

Ce faisant, un attaquant est à même d'opérer en toute discretion (si tant est que ses actions le soient) depuis une base (le client C2, la DLL injectée) subrepticement cachée au sein d'un processus anodin.
Tout l'enjeu réside ainsi dans l'obfuscation instillée au sein de l'injecteur afin de garantir de l'indétectabilité de l'injection.
Pour ce faire, plusieurs techniques sont mises en oeuvres afin de contourner les points de détection classiques tels que les API en userland de Windows, souvent hookées par les systèmes de détection, ou encore les analyseurs statiques tels Microsoft Defender ayant la capacité de reconnaître des schémas de codes malicieux.

## Decription détaillée des briques

Si la structure macroscopique est claire, un injecteur et une DLL injecté, le projet possède malgré des ramifications plus importantes qu'il n'y paraît.

> [!info] Intentions
> L'architecture se veut la plus modulaire possible, et le projet en tant que tel entend servir de librairie durable et réutilisable.
> Toutefois, celle-ci ne saurait être que pûrement pragmatique, car avant tout source d'un apprentissage des différents usages et différentes stratégies offensives à mettre en oeuvre dans un tel contexte.

### Architecture

Pour comprendre l'architecture du projet, il est nécessaire de revenir :

1. À l'itention du payload runner.
2. Aux contraites systémiques de Windows.

Dans un premier temps, il est nécessaire de déterminer le processus cible, afin d'agir en son sein.
Pour ce faire, l'injecteur à recourt à des méthodes classiques telles que le _PEB Walk_ (implémenté en C d'abord), et le _Manual Mapping_.
Il est ainsi possible de _charger la DLL en mémoire_ -- ie. copier cette dernière au sein de la mémoire virtuelle du processus cible -- avant de lui donner le contrôle de l'exécution, et donc d'appeller `DllMain`.

Toutefois, pour rendre le programme nouvelle chargé en mémoire au sein du processus cible fonctionnel, il faut corriger manuellement un certain nombre de structure internes qui sont dépendantes de l'environnement d'exécution, c'est à dire du _processus_ lui-même.
Cette opération ne peut être réalisée simplemennt de l'extérieur ; et subséquemment, c'est un _**C Stub**_ compilé en _Independant Position_ qui est chargé de la mise en fonctionnement de la DLL.
Cette étape intervient après la résolution des librairies locale au processus ciblé par un _**ASM Stub**_ implémentant le PEB Walk, et complétant une "structure partagée" stockée dans le même temps en mémoire que l'est écrite la DLL afin de communiquer des adresses nécessaires à la réalisation des appels à `GetProcAddress`.[^1]
[^1]: Les contraintes inhérentes à ces opérations seront détaillées dans des sections ultérieures.

```
Injecteur (host)                     Processus cible
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

### Structure du projet

TODO : Mettre à jour le graphe de la structure du projet avec les direct-syscalls.

La structure du projet est la suivante :

```sh
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

## Injection distante

- schéma clair des étapes,
- API utilisées,
- erreurs possibles et mitigations,
- justification du processus cible choisi.

## Techniques mises en œuvre

| Technique                | Description                                                                                                                   |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| **Manual Mapping**       | Copie manuelle du PE en mémoire distante, sans `LoadLibrary`                                                                  |
| **API Hashing (FNV-1a)** | Résolution des API Win32 au runtime via parcours du PEB — aucun import suspect dans l'IAT                                     |
| **ASM stub PIC**         | Shellcode x64 position-independent : parcours du PEB dans le processus cible pour résoudre `LoadLibraryA` et `GetProcAddress` |
| **C Loader stub PIC**    | Stub compilé sans CRT : relocation de base, résolution de l'IAT, appel du `DllMain`                                           |

-

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

| Fichier            | Description             |
| ------------------ | ----------------------- |
| `dll-injector.exe` | L'injecteur             |
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
