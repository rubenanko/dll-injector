#ifndef DLL_INJECTOR_H
#define DLL_INJECTOR_H

#include <windows.h>
#include <string.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>
#include "pe-parser.h"

/**
 * @brief Structure de configuration transmise au stub de chargement distant.
 *
 * Contient les adresses des fonctions de résolution et l'adresse de base
 * de la DLL mappée, nécessaires au stub C pour finaliser le chargement.
 */
typedef struct _MANUAL_MAPPING_DATA {
  LPVOID pLoadLibraryA;   /**< Adresse de LoadLibraryA, résolue par le stub ASM. */
  LPVOID pGetProcAddress; /**< Adresse de GetProcAddress, résolue par le stub ASM. */
  LPVOID pBaseAddress;    /**< Adresse de base de la DLL dans le processus cible. */
  LPVOID pCStubAddress;   /**< Adresse du stub C dans le processus cible. */
} MANUAL_MAPPING_DATA, *PMANUAL_MAPPING_DATA;

DWORD ProcessWalking(char* exeFileName);
LPVOID MannualMappingDll(HANDLE hProcess, PIMAGE_PE_FILE pe);
HANDLE injectDll(DWORD dwProcessId, const char* dllPath, LPVOID* remoteBuffer);
HANDLE injectManualMappingStub(HANDLE hProcess, PMANUAL_MAPPING_DATA pData, LPVOID pAsmStub, DWORD asmStubSize, LPVOID pCStub, DWORD cStubSize);

#endif // !DLL_INJECTOR_H
