
#ifndef __MAIN_H__
#define __MAIN_H__

///////////////////////////////////////////////
// (c) h4lf-jiffie (dohmatob elvis dopgima)
//////////////////////////////////////////////
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define __DLL_PSEUDO__ "BASICPROXY"

/*  To use this exported function of dll, include this header
 *  in your project.
 */

#ifdef BUILD_DLL
    #define DLL_EXPORT __declspec(dllexport)
#else
    #define DLL_EXPORT __declspec(dllimport)
#endif


#ifdef __cplusplus
extern "C"
{
#endif

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID);
void HookSleepEx(void);
void UnhookSleepEx(void);

#ifdef __cplusplus
}
#endif

#endif // __MAIN_H__
