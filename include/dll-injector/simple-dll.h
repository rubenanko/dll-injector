#ifndef SIMPLE_DLL_H
#define SIMPLE_DLL_H

#pragma once

#include <windows.h>
#include <shellapi.h>

/* Macro d'exportation DLL. */
#define EXPORT __declspec(dllexport)

/* UTF16("str") == L"str" — conversion de chaîne littérale en UTF-16. */
#define _UTF16(x)   L##x
#define UTF16(x)    _UTF16(x)

/* Intervalle de rafraîchissement de la notification en millisecondes. */
#define SLEEPTIME 500

extern int g_sleepTime;
extern int* g_sleepTime_addr;
DWORD WINAPI Notify(LPVOID param);
EXPORT void CALLBACK notifyentry(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);
EXPORT void CALLBACK TestFunction(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);

#endif // !SIMPLE_DLL_H
