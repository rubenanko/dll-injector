#ifndef PE_PARSER_H
#define PE_PARSER_H

#include "../windows/pe-format.h"
#include <stdbool.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <winnt.h>
#include "../utils/macros.h"
#include "utils/stdio-sec.h"

PIMAGE_PARSED ParsePE(const char* fileName);
bool isValidImage(const char* fileName);

#endif // !PE_PARSER_H
