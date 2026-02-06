#ifndef PE_PARSER_H
#define PE_PARSER_H

#include "../windows/pe-format.h"
#include <stdbool.h>

PIMAGE_PARSED ParsePE(const char* fileName);
bool isValidImage(const char* fileName);

#endif // !PE_PARSER_H
