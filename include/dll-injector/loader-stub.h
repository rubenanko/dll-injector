#ifndef LOADER_STUB_H
#define LOADER_STUB_H

#include "dll-injector.h"

DWORD WINAPI C_LoaderStub(PMANUAL_MAPPING_DATA pData);
void C_LoaderStub_End(void);

#endif // !LOADER_STUB_H
