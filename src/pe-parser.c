#include "../include/dll-injector/pe-parser.h"
#include "windows/pe-format.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <winnt.h>

bool isValidImage(const char* fileName){
  FILE* file;
  IMAGE_DOS_HEADER tmpImageDosHeader;

  file = fopen(fileName, "rb");
  if (file == NULL) {
    return false;
  }

  int fseekRC = fseek(file, 0, SEEK_SET);
  if (fseekRC) {
    fprintf(stderr, "Error: fseek returns %d\n", errno);
    fclose(file);
    return false;
  }

  int freadRC = fread(&tmpImageDosHeader, sizeof(tmpImageDosHeader), 1, file);
  
  return false;
}

PIMAGE_PARSED ParsePE(const char *fileName){
  
  PIMAGE_PARSED imageParsed = (PIMAGE_PARSED)malloc(sizeof(IMAGE_PARSED));

  if (isValidImage()) {
  
  }

  return imageParsed;
}
