#ifndef SIMPLE_DLL_H
#define SIMPLE_DLL_H

#pragma once

//-----------
// Headers
#include <windows.h>
#include <shellapi.h>

//-----------
// DLL
//#ifdef SDLL_EXPORTS
#define EXPORT __declspec(dllexport)
//#else
//#define EXPORT __declspec(dllimport)
//#endif

//-----------
// MACROS

// UTF16("str") == L"str"  // Wide Character String / UTF-16
#define _UTF16(x)   L##x
#define UTF16(x)    _UTF16(x)
#define SLEEPTIME 500

//-----------
// Functions
extern int g_sleepTime;
extern int* g_sleepTime_addr;
DWORD WINAPI Notify(LPVOID param);
EXPORT void CALLBACK notifyentry(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);
EXPORT void CALLBACK TestFunction(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);

#endif // !SIMPLE_DLL_H
