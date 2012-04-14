/////////////////////////////////////////
// (c) d0hm4t06 3. d0p91m4 (RUDE-BOI)
////////////////////////////////////////

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#endif

#include <windows.h>
#include <io.h>
#include <stdlib.h> 
#include <stdio.h>
#include <TlHelp32.h>
#include "inlinedetours.h"

#define __PINBALL_SIGNATURE__ "\x01\x30\x8B\x10\x81\xFA\x00\xCA\x9A\x3B"
#define __DLL_PSEUDO__ "PINBALL-SPY"

void ExtractScore(void);
void DisplayScore(void);
extern "C" void TrapScore(void);
extern "C" void UntrapScore(void);
