///////////////////////////////////////////
// (c) d0hm4t06 3. d0p91m4 (h4lf-jiffie)
//////////////////////////////////////////

#pragma once

#include "stdafx.h"

// ERROR CODES
#define DETOUR_NOERROR 0x00000000
#define DETOUR_ERROR_CAVE_TOOSMALL 0x00000001
#define DETOUR_ERROR_PAGE_PROTECTION 0x00000002
#define DETOUR_ERROR_NONEXISTENT_TRANSACTION 0x00000003
#define DETOUR_ERROR_NO_MEMORY 0x00000004
#define DETOUR_ERROR_INVALID_OPERATION 0x00000005

/////////////////////
// g_detours ADT
////////////////////
typedef struct detour_struct
{
	PVOID pTarget;               // pointer to target function or instruction block
	PVOID pDetour;               // pointer to detour function or instruction block
	DWORD dwOriginalOpcodes; // number of bytes to be detoured from the start of target function, or size of target block
	PBYTE pTrampoline2Target;           // pointer to instruction block which reroutes to the original/undetoured function or instruction block

	detour_struct(PVOID _pTarget, PVOID _pDetour, DWORD _dwOriginalOpcodes)
	{
		pTarget = _pTarget;
		pDetour = _pDetour;
		dwOriginalOpcodes = _dwOriginalOpcodes;
	}

	~detour_struct(void)
	{
		if (pTrampoline2Target)
		{
			delete []pTrampoline2Target;
		}
	}
} detour_t;

typedef BOOL (WINAPI *BAD_MBI_FILTER)(MEMORY_BASIC_INFORMATION);

///////////////////////////
// Function declarations
//////////////////////////
extern "C" void FindSignatureInProcessMemory(HANDLE hProcess, PBYTE pSignature, DWORD dwSignature, std::vector<unsigned long>& hits, BAD_MBI_FILTER filter = 0);
extern "C" void CreateConsole(const char *title=0, DWORD wAttributes=FOREGROUND_GREEN | FOREGROUND_INTENSITY);
extern "C" DWORD UninstallDetour(PVOID *ppTarget);
extern "C" DWORD InstallDetour(PVOID *ppTarget, PVOID pDetour, DWORD dwOrignalOpcodesSize);
static void MakeJmp(DWORD dwSrcAddr, DWORD dwDstAddr, PBYTE pBuf);
static PVOID AllocateCodecave(DWORD dwSize);
static BOOL SuspendAllOtherThreads(void);
static BOOL ResumeAllOtherThreads(void);
static void EnterCriticalCodeSection(void);
static void LeaveCriticalCodeSection(void);
