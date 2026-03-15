#include <dll-injector/pe-parser.h>
#include <winnt.h>

/**
 * @brief Lit un fichier PE valide et charge ses données brutes en mémoire.
 *
 * @param fileName Chemin vers le fichier PE à charger.
 * @param pe Pointeur vers la structure IMAGE_PE_FILE à remplir.
 * @return 0 en cas de succès, -1 si le fichier n'est pas une image PE valide.
 */
int SetRawData(const char *fileName, PIMAGE_PE_FILE pe)
{
  FILE *fp;
  long fileSize;

  if (IsValidImage(fileName) == false) {
    return -1;
  }

  fp = fopen(fileName, "rb");
  fseek(fp, 0, SEEK_END);
  fileSize = ftell(fp);
  pe->RawData = malloc(fileSize);
  pe->SizeOfFile = fileSize;

  fseek(fp,0,SEEK_SET);
  fread(pe->RawData, fileSize,1,fp);

  fclose(fp);
  return 0;
}

/**
 * @brief Vérifie qu'un fichier est une image PE64 (PE32+) valide.
 *
 * Contrôle successivement : la signature DOS (MZ), la signature NT (PE),
 * et le magic de l'en-tête optionnel (IMAGE_NT_OPTIONAL_HDR64_MAGIC).
 *
 * @param fileName Chemin vers le fichier à valider.
 * @return true si le fichier est une image PE32+ valide, false sinon.
 */
bool IsValidImage(const char *fileName) {
  FILE *fp;
  size_t retRead;
  IMAGE_DOS_HEADER tmpImageDosHeader;
  DWORD ntSignature;
  WORD peFileType;
  long fileSize;

  fp = fopen(fileName, "rb");
  if (fp == NULL) {
    return false;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek");
    fclose(fp);
    return false;
  }
  fileSize = ftell(fp);
  if (fileSize < 0) {
    perror("ftell");
    fclose(fp);
    return false;
  }

  if (!seek_checked(fp, 0, fileSize)) {
    fclose(fp);
    return false;
  }
  retRead = fread(&tmpImageDosHeader, sizeof(tmpImageDosHeader), 1, fp);
  if (retRead != 1) {
    fprintf(stderr, "fread() failed: %zu\n", retRead);
    fclose(fp);
    return false;
  }

  if (tmpImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
    fclose(fp);
    return false;
  }

  /* Vérification que l'en-tête PE est dans les limites du fichier. */
  if (tmpImageDosHeader.e_lfanew < 0 ||
      (long)tmpImageDosHeader.e_lfanew + (long)sizeof(DWORD) > fileSize) {
    fclose(fp);
    return false;
  }

  if (!seek_checked(fp, (long)tmpImageDosHeader.e_lfanew, fileSize)) {
    fclose(fp);
    return false;
  }
  retRead = fread(&ntSignature, sizeof(ntSignature), 1, fp);
  if (retRead != 1 || ntSignature != IMAGE_NT_SIGNATURE) {
    fclose(fp);
    return false;
  }

  /* Vérification que la position du magic de l'en-tête optionnel est dans les limites. */
  {
    long optMagicOffset = (long)tmpImageDosHeader.e_lfanew + (long)sizeof(DWORD) + (long)sizeof(IMAGE_FILE_HEADER);
    if (optMagicOffset < 0 || optMagicOffset + (long)sizeof(WORD) > fileSize) {
      fclose(fp);
      return false;
    }
    if (!seek_checked(fp, optMagicOffset, fileSize)) {
      fclose(fp);
      return false;
    }
  }

  retRead = fread(&peFileType, sizeof(peFileType), 1, fp);
  if (retRead != 1) {
    fprintf(stderr, "fread() failed: %zu\n", retRead);
    fclose(fp);
    return false;
  }

  if (peFileType != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    fclose(fp);
    return false;
  }

  fclose(fp);
  return true;
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
