#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <windows/pe-format.h>
#include <stdbool.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <winnt.h>
#include <utils/macros.h>
#include <utils/stdio-sec.h>

void SetRawDataBis(PVOID pe_raw_data, int size_pe_raw_data, PIMAGE_PE_FILE pe);
PVOID RvaToPtr(PIMAGE_PE_FILE pe, DWORD rva);

#endif // !PE_PARSER_H
