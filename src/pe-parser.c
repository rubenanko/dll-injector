#include "../include/dll-injector/pe-parser.h"
#include "windows/pe-format.h"
#include <minwinbase.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <winnt.h>


#define NBYTES(x) sizeof(x)/8

bool isValidImage(const char* fileName){
  FILE* fp;
  size_t retRead;
  int retSeek;
  IMAGE_DOS_HEADER tmpImageDosHeader;

  fp = fopen(fileName, "rb");
  if (fp == NULL) {
    return false;
  }

  retSeek = fseek(fp, 0, SEEK_SET);
  if (retSeek) {
    fprintf(stderr, "Error: fseek returns %d\n", errno);
    fclose(fp);
    return false;
  }

  retRead = fread(&tmpImageDosHeader, sizeof(tmpImageDosHeader), 1, fp);
  if (retRead != NBYTES(tmpImageDosHeader)) {
    fprintf(stderr, "fread() failed: %zu\n", retRead);
    fclose(fp);
    return false;
  }

  // verify e_magic
  // verify pe32+
  
  return true;
}

PIMAGE_PARSED ParsePE(const char *fileName){
  
  PIMAGE_PARSED imageParsed = (PIMAGE_PARSED)malloc(sizeof(IMAGE_PARSED));

  if (isValidImage()) {
  
  }

  return imageParsed;
}
