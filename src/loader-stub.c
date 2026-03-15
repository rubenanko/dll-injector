#include "dll-injector/loader-stub.h"

/**
 * @brief Stub de chargement PIC exécuté dans l'espace mémoire du processus cible.
 *
 * Effectue dans l'ordre : la relocation de base (si delta non nul), la résolution
 * de l'IAT (imports par nom et par ordinal), puis l'appel du DllMain avec
 * DLL_PROCESS_ATTACH.
 *
 * @param pData Pointeur vers la structure MANUAL_MAPPING_DATA contenant l'adresse
 *              de base ainsi que les pointeurs vers LoadLibraryA et GetProcAddress.
 * @return 0 à la fin de l'exécution.
 */
DWORD WINAPI C_LoaderStub(PMANUAL_MAPPING_DATA pData) {

  /* Récupération des en-têtes PE depuis l'adresse de base. */
  BYTE *pBase = (BYTE *)pData->pBaseAddress;
  IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER *)pBase;
  IMAGE_NT_HEADERS *pNt = (IMAGE_NT_HEADERS *)(pBase + pDos->e_lfanew);

  /* Delta = adresse réelle − adresse préférée (ImageBase). */
  ptrdiff_t delta = (ptrdiff_t)pBase - pNt->OptionalHeader.ImageBase;

  /* --- Étape 1 : Relocation de base --- */
  if (delta != 0) {
    IMAGE_DATA_DIRECTORY *pRelocDir =
        &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pRelocDir->Size > 0 && pRelocDir->VirtualAddress > 0) {
      IMAGE_BASE_RELOCATION *pReloc =
          (IMAGE_BASE_RELOCATION *)(pBase + pRelocDir->VirtualAddress);

      while (pReloc->VirtualAddress != 0) {
        /* Nombre d'entrées = (taille du bloc − taille de l'en-tête) / 2 octets. */
        DWORD entriesCount =
            (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(WORD);
        WORD *pRelativeInfo =
            (WORD *)(pReloc + 1);

        for (DWORD i = 0; i < entriesCount; i++) {
          if (pRelativeInfo[i] != 0) {
            /* 4 bits de poids fort = type ; 12 bits de poids faible = offset.
             * IMAGE_REL_BASED_DIR64 (0xA) pour les images 64 bits. */
            if ((pRelativeInfo[i] >> 12) == IMAGE_REL_BASED_DIR64) {
              ULONG_PTR *pPatch = (ULONG_PTR *)(pBase + pReloc->VirtualAddress +
                                                (pRelativeInfo[i] & 0xFFF));
              *pPatch += delta;
            }
          }
        }
        pReloc =
            (IMAGE_BASE_RELOCATION *)((BYTE *)pReloc + pReloc->SizeOfBlock);
      }
    }
  }

  /* --- Étape 2 : Résolution de l'IAT --- */
  IMAGE_DATA_DIRECTORY *pImportDir =
      &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  if (pImportDir->Size > 0 && pImportDir->VirtualAddress > 0) {
    IMAGE_IMPORT_DESCRIPTOR *pImportDesc =
        (IMAGE_IMPORT_DESCRIPTOR *)(pBase + pImportDir->VirtualAddress);

    while (pImportDesc->Name != 0) {
      char *szModName = (char *)(pBase + pImportDesc->Name);

      typedef HMODULE(WINAPI * fnLoadLibraryA)(LPCSTR);
      HMODULE hMod = ((fnLoadLibraryA)pData->pLoadLibraryA)(szModName);

      /* Thunk original (noms) et thunk courant (adresses à écrire). */
      IMAGE_THUNK_DATA *pThunk =
          (IMAGE_THUNK_DATA *)(pBase + pImportDesc->FirstThunk);
      IMAGE_THUNK_DATA *pOrigThunk =
          (IMAGE_THUNK_DATA *)(pBase + pImportDesc->OriginalFirstThunk);

      /* Repli sur FirstThunk si OriginalFirstThunk est absent. */
      if (pImportDesc->OriginalFirstThunk == 0)
        pOrigThunk = pThunk;

      while (pOrigThunk->u1.AddressOfData != 0) {
        typedef FARPROC(WINAPI * fnGetProcAddress)(HMODULE, LPCSTR);
        FARPROC pFunc = NULL;

        if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
          /* Import par ordinal. */
          pFunc = ((fnGetProcAddress)pData->pGetProcAddress)(
              hMod, (LPCSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
        } else {
          /* Import par nom. */
          IMAGE_IMPORT_BY_NAME *pIBN =
              (IMAGE_IMPORT_BY_NAME *)(pBase + pOrigThunk->u1.AddressOfData);
          pFunc = ((fnGetProcAddress)pData->pGetProcAddress)(
              hMod, (LPCSTR)pIBN->Name);
        }

        /* Remplacement du nom par l'adresse résolue dans l'IAT. */
        pThunk->u1.Function = (ULONG_PTR)pFunc;

        pThunk++;
        pOrigThunk++;
      }
      pImportDesc++;
    }
  }

  /* --- Étape 3 : Appel du DllMain avec DLL_PROCESS_ATTACH --- */
  if (pNt->OptionalHeader.AddressOfEntryPoint != 0) {
    typedef BOOL(WINAPI * fnDllMain)(HMODULE, DWORD, LPVOID);
    fnDllMain pDllMain =
        (fnDllMain)(pBase + pNt->OptionalHeader.AddressOfEntryPoint);

    pDllMain((HMODULE)pBase, DLL_PROCESS_ATTACH, NULL);
  }

  return 0;
}

/**
 * @brief Marqueur de fin du stub C, utilisé pour calculer sa taille en mémoire.
 *
 * @note Cette fonction ne retourne rien ; elle sert uniquement de marqueur de fin.
 */
void C_LoaderStub_End(void) {}
