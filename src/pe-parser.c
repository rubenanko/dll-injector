#include <dll-injector/pe-parser.h>
#include <winnt.h>

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
 * IsValidImage - checks if the given file is a valid PE32+ image
 *
 * @fileName: the name of the file to check
 *
 * Returns true if the file is a valid PE32+ image, false otherwise
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

  // Ensure PE header is within bounds
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

  // Optional header magic location must be in bounds
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
 * RvaToPtr - converts a Relative Virtual Address (RVA) to a file pointer
 *
 * @pe: pointer to the IMAGE_PE_FILE structure representing the PE file
 * @rva: the Relative Virtual Address to convert
 *
 * Returns a pointer to the corresponding location in the file, or NULL if the RVA is invalid
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

