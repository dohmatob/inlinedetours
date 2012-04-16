///////////////////////////////////////////
// (c) d0hm4t06 3. d0p91m4 (half-jiffie)
//////////////////////////////////////////

#include "stdafx.h"

DWORD dwCmpEdxAddr = 0;
DWORD dwExtractScoreRetAddr;
DWORD dwPreviousScore = 0;
DWORD dwCurrentScore;

////////////////////////////////////////////////////////////////////////
// This callback is invoked by ExtractScore to display current score
///////////////////////////////////////////////////////////////////////
void DisplayScore(void)
{
	if (dwCurrentScore < dwPreviousScore)
	{
		printf("[%s] Game restarting ?\n", __DLL_PSEUDO__);
	}
	printf("[%s] Current score is %d.\n", __DLL_PSEUDO__, dwCurrentScore);
	dwPreviousScore = dwCurrentScore;
}

////////////////////////////////
// The score-extracting hook
///////////////////////////////
void __declspec(naked) ExtractScore(void)
{
	// backup edx (this contains the score :))
	__asm mov dwCurrentScore, edx

	// invoke handler
	__asm pushad // save registers
	__asm pushfd // save eflags
	DisplayScore(); // this will corrupt the current thread's context
	__asm popfd // restore registers
	__asm popad // restore eflags

	// finally
	__asm push dwExtractScoreRetAddr // saved return address
	__asm ret // return like a ninja
}

/////////////////////////////////////////////////////////////
// This is invoked (by you) to unset the ExtracScore hook
////////////////////////////////////////////////////////////
void UntrapScore(void)
{
	UninstallDetour((PVOID *)&dwCmpEdxAddr);
}

///////////////////////////////////////////////////////////////////////////
// Bad MBI filter to help search for pinball signature in process image
//////////////////////////////////////////////////////////////////////////
BOOL WINAPI BadMbiFilterForPinballSignature(MEMORY_BASIC_INFORMATION mbi)
{
	return ((mbi.Protect != PAGE_EXECUTE_READ) && (mbi.Protect != PAGE_EXECUTE_READWRITE)) || (mbi.Type != MEM_IMAGE); // basic filter
}

//////////////////////////////////////////////////////////
// This is invoked by you to set the ExtractScore hook
/////////////////////////////////////////////////////////
void TrapScore(void)
{
	linkedlist_t *hits = new linkedlist_t; // this will hold addresses at which pinball signature if found

	// find pinball signature in process image
	FindSignatureInProcessMemory(GetCurrentProcess(), (PBYTE)__PINBALL_SIGNATURE__, \
		strlen((const char *)__PINBALL_SIGNATURE__), hits, BadMbiFilterForPinballSignature);
	if(hits->empty())
	{
		printf("[%s] Couldn't find pinball signature; process is certainly not a pinball session.\n", __DLL_PSEUDO__);
		return;
	}

	if (hits->dwSize > 1)
	{
		printf("[%s] Found pinball signature at %d addresses. The proposed signature is surely too short and thus very imprecise. "
			"Can't continue.\n", __DLL_PSEUDO__, hits->dwSize);
		return;
	}

	// detour installation proper

    // MOV DWORD PTR DS:[EAX], ESI
    // MOV EDX, DWORD PTR DS:[EAX]
    // CMP EDX, 3B9ACA00 <-- install detour at the begining of this instruction 6-byte instruction
	dwCmpEdxAddr = (DWORD)(hits->head->data) + 4; // advance 4 bytes ahead
	InstallDetour((PVOID *)&dwCmpEdxAddr, (PVOID)ExtractScore, 0x6);
	dwExtractScoreRetAddr = dwCmpEdxAddr;
}



