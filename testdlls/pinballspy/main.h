
#ifndef __MAIN_H__
#define __MAIN_H__

///////////////////////////////////////////////
// (c) h4lf-jiffie (dohmatob elvis dopgima)
//////////////////////////////////////////////
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "inlinedetours.h"

#define __PINBALL_SIGNATURE__ "\x01\x30\x8B\x10\x81\xFA\x00\xCA\x9A\x3B"
#define __DLL_PSEUDO__ "PINBALL-SPY"

#ifdef __cplusplus
extern "C"
{
#endif

extern "C" __declspec(dllexport) BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID);
extern "C" __declspec(dllexport) void TrapScore(void);
extern "C" __declspec(dllexport) void UntrapScore(void);

#ifdef __cplusplus
}
#endif

#endif // __MAIN_H__
