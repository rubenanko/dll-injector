#include "../include/dll-injector/pe-parser.h"
#include "windows/pe-format.h"
#include <minwinbase.h>
#include <minwindef.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <winnt.h>

#define NBYTES(x) (sizeof(x))
#define NITEMS(arr) (sizeof(arr) / sizeof((arr)[0]))

static bool seek_checked(FILE *fp, long offset, long size) {
  if (offset < 0 || offset > size) {
    return false;
  }
  return fseek(fp, offset, SEEK_SET) == 0;
}

bool isValidImage(const char *fileName) {
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

PIMAGE_PARSED ParsePE(const char *fileName) {
  PIMAGE_PARSED imageParsed = (PIMAGE_PARSED)malloc(sizeof(IMAGE_PARSED));

  if (isValidImage(fileName)) {
  }

  return imageParsed;
}
