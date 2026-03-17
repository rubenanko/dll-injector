#ifndef LOADER_STUB_H
#define LOADER_STUB_H

#include <dll-injector/dll-injector.h>

LPVOID getC_LoaderStubAddress(void);
DWORD WINAPI C_LoaderStub(PMANUAL_MAPPING_DATA pData);
void C_LoaderStub_End(void);

#endif // !LOADER_STUB_H
