#include <dll-injector/pe-parser.h>
#include <winnt.h>

/**
 * @brief Initialise un objet IMAGE_PE_FILE passé par référence sur la base du tableau du bytecode d'un fichier PE encapsulé dans un tableau pe_raw_data de taille size_pe_raw_data
 *
 * @param pe_raw_data Pointeur sur le tableau portant le bytecode du fichier PE
 * @param size_pe_raw_data Taille du tableau pe_raw_data
 * @param pe Pointeur vers la structure IMAGE_PE_FILE à remplir.
 */
void SetRawDataBis(PVOID pe_raw_data, int size_pe_raw_data, PIMAGE_PE_FILE pe)
{

  pe->RawData = pe_raw_data;
  pe->SizeOfFile = size_pe_raw_data;

}

/**
 * @brief Convertit une adresse virtuelle relative (RVA) en pointeur de fichier.
 *
 * Parcourt les sections du PE pour trouver celle qui contient le RVA et calcule
 * le décalage correspondant dans les données brutes.
 *
 * @param pe Pointeur vers la structure IMAGE_PE_FILE représentant le fichier PE.
 * @param rva Adresse virtuelle relative à convertir.
 * @return Pointeur vers l'emplacement correspondant dans les données brutes,
 *         ou NULL si le RVA n'appartient à aucune section.
 */
PVOID RvaToPtr(PIMAGE_PE_FILE pe, DWORD rva) {
  int i;
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pe->RawData;
  PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)((BYTE*)pe->RawData + dosHeader->e_lfanew);

  int numberOfSections = NtHeader->FileHeader.NumberOfSections;

  PIMAGE_SECTION_HEADER  sectionHeader = (PIMAGE_SECTION_HEADER)(NtHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + NtHeader->FileHeader.SizeOfOptionalHeader);

  for (i = 0; i < numberOfSections; i++) {
      if (rva >= sectionHeader->VirtualAddress &&
          rva < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {

          DWORD fileOffset = sectionHeader->PointerToRawData + (rva - sectionHeader->VirtualAddress);

          return (PVOID)((BYTE*)pe + fileOffset );
      }
      sectionHeader ++;
  }
  return NULL;
}
