#include "loader-stub.h"

DWORD WINAPI C_LoaderStub(PMANUAL_MAPPING_DATA pData) {

  // 1. Récupérer les headers depuis l'adresse de base
  BYTE *pBase = (BYTE *)pData->pBaseAddress;
  IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER *)pBase;
  IMAGE_NT_HEADERS *pNt = (IMAGE_NT_HEADERS *)(pBase + pDos->e_lfanew);

  // Calcul du Delta : Adresse réelle - Adresse préférée
  // On utilise un type entier de la taille d'un pointeur (ULONG_PTR ou
  // ptrdiff_t)
  ptrdiff_t delta = (ptrdiff_t)pBase - pNt->OptionalHeader.ImageBase;

  // 2. LA RELOCATION (Si le delta n'est pas nul, on doit patcher la DLL)
  if (delta != 0) {
    // Trouver la table de relocation dans les Data Directories
    IMAGE_DATA_DIRECTORY *pRelocDir =
        &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pRelocDir->Size > 0 && pRelocDir->VirtualAddress > 0) {
      // Pointer sur le premier bloc de relocation
      IMAGE_BASE_RELOCATION *pReloc =
          (IMAGE_BASE_RELOCATION *)(pBase + pRelocDir->VirtualAddress);

      // Parcourir tous les blocs
      while (pReloc->VirtualAddress != 0) {
        // Nombre d'entrées dans ce bloc (Taille du bloc - Taille du header / 2
        // octets par entrée)
        DWORD entriesCount =
            (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(WORD);
        WORD *pRelativeInfo =
            (WORD *)(pReloc + 1); // Les données juste après le header

        for (DWORD i = 0; i < entriesCount; i++) {
          if (pRelativeInfo[i] != 0) {
            // Les 4 bits de poids fort = Type, les 12 bits de poids faible =
            // Offset 0xA = IMAGE_REL_BASED_DIR64 (Pour du 64-bit) 0x3 =
            // IMAGE_REL_BASED_HIGHLOW (Pour du 32-bit)
            if ((pRelativeInfo[i] >> 12) == IMAGE_REL_BASED_DIR64) {
              // On trouve l'adresse absolue à patcher et on ajoute le delta
              ULONG_PTR *pPatch = (ULONG_PTR *)(pBase + pReloc->VirtualAddress +
                                                (pRelativeInfo[i] & 0xFFF));
              *pPatch += delta;
            }
          }
        }
        // Passer au bloc suivant
        pReloc =
            (IMAGE_BASE_RELOCATION *)((BYTE *)pReloc + pReloc->SizeOfBlock);
      }
    }
  }

  // 3. LA RÉSOLUTION DE L'IAT
  IMAGE_DATA_DIRECTORY *pImportDir =
      &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  if (pImportDir->Size > 0 && pImportDir->VirtualAddress > 0) {
    // On pointe sur le premier descripteur d'import
    IMAGE_IMPORT_DESCRIPTOR *pImportDesc =
        (IMAGE_IMPORT_DESCRIPTOR *)(pBase + pImportDir->VirtualAddress);

    // Boucle sur chaque DLL parente (jusqu'à un descripteur vide)
    while (pImportDesc->Name != 0) {
      char *szModName = (char *)(pBase + pImportDesc->Name);

      // 1. Charger la DLL dépendante
      typedef HMODULE(WINAPI * fnLoadLibraryA)(LPCSTR);
      HMODULE hMod = ((fnLoadLibraryA)pData->pLoadLibraryA)(szModName);

      // 2. Parcourir les fonctions demandées dans cette DLL
      // Thunk original (le nom) et Thunk actuel (là où on écrit l'adresse)
      IMAGE_THUNK_DATA *pThunk =
          (IMAGE_THUNK_DATA *)(pBase + pImportDesc->FirstThunk);
      IMAGE_THUNK_DATA *pOrigThunk =
          (IMAGE_THUNK_DATA *)(pBase + pImportDesc->OriginalFirstThunk);

      // Si OriginalFirstThunk est nul (cas rare), on utilise FirstThunk
      if (pImportDesc->OriginalFirstThunk == 0)
        pOrigThunk = pThunk;

      while (pOrigThunk->u1.AddressOfData != 0) {
        typedef FARPROC(WINAPI * fnGetProcAddress)(HMODULE, LPCSTR);
        FARPROC pFunc = NULL;

        // Est-ce un import par Ordinal ou par Nom ?
        if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
          // Import par numéro (ordinal)
          pFunc = ((fnGetProcAddress)pData->pGetProcAddress)(
              hMod, (LPCSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
        } else {
          // Import par nom
          IMAGE_IMPORT_BY_NAME *pIBN =
              (IMAGE_IMPORT_BY_NAME *)(pBase + pOrigThunk->u1.AddressOfData);
          pFunc = ((fnGetProcAddress)pData->pGetProcAddress)(
              hMod, (LPCSTR)pIBN->Name);
        }

        // 3. ÉCRITURE CRITIQUE : On remplace le nom par l'adresse réelle
        pThunk->u1.Function = (ULONG_PTR)pFunc;

        pThunk++;
        pOrigThunk++;
      }
      pImportDesc++; // Passer à la DLL suivante
    }
  }

  // 4. APPEL DU DLLMAIN
  if (pNt->OptionalHeader.AddressOfEntryPoint != 0) {
    typedef BOOL(WINAPI * fnDllMain)(HMODULE, DWORD, LPVOID);
    fnDllMain pDllMain =
        (fnDllMain)(pBase + pNt->OptionalHeader.AddressOfEntryPoint);

    // On appelle DllMain avec DLL_PROCESS_ATTACH
    pDllMain((HMODULE)pBase, DLL_PROCESS_ATTACH, NULL);
  }

  return 0;
}
