#ifndef __MAIN_H__
#define __MAIN_H__

///////////////////////////////////////////////
// (c) h4lf-jiffie (dohmatob elvis dopgima)
//////////////////////////////////////////////
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define __DLL_PSEUDO__ "BASICPROXY"

extern "C" void HookSleepEx(void);
extern "C" void UnhookSleepEx(void);

#endif // __MAIN_H__
