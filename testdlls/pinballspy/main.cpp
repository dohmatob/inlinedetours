///////////////////////////////////////////
// (c) d0hm4t06 3. d0p91m4 (half-jiffie)
//////////////////////////////////////////

#include "main.h"

DWORD dwCmpEdxAddr = 0;
DWORD dwExtractScoreRetAddr;
DWORD dwPreviousScore = 0;
DWORD dwCurrentScore;

void CreateConsole(void)
{
	HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!hStd)
	{
		AllocConsole();
		hStd = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTitle(_T(__DLL_PSEUDO__));
		SetConsoleTextAttribute(hStd, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	}
	freopen("CONOUT$", "w", stdout);
}

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
	asm __volatile__(
        "int3;"
        "movl %%edx, %0;"
        : "=r" (dwCurrentScore)
        );

    asm __volatile__(
         "pusha;"
         "pushf;"
         );
    DisplayScore();
    asm __volatile__(
         "popf;"
         "popa;"
         );

    asm __volatile__(
        "jmp *%0;"
        :
        : "r" (dwExtractScoreRetAddr)
        );
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
	std::vector<unsigned long> hits;

	// find pinball signature in process image
	FindSignatureInProcessMemory(GetCurrentProcess(), (PBYTE)__PINBALL_SIGNATURE__, \
 		strlen((const char *)__PINBALL_SIGNATURE__), hits, BadMbiFilterForPinballSignature);
	if(hits.empty())
	{
		printf("[%s] Couldn't find pinball signature; process is certainly not a pinball session.\n", __DLL_PSEUDO__);
		return;
	}

	if (hits.size() > 1)
	{
		printf("[%s] Found pinball signature at %d addresses. The proposed signature is surely too short and thus very imprecise. "
			"Can't continue.\n", __DLL_PSEUDO__, hits.size());
		return;
	}

	// detour installation proper
	dwCmpEdxAddr = ((DWORD)*(hits.begin())) + 4;
	InstallDetour((PVOID *)&dwCmpEdxAddr, (PVOID)ExtractScore, 0x6);
	dwExtractScoreRetAddr = dwCmpEdxAddr;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                                         )
{
        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:
                DisableThreadLibraryCalls(hModule);
                CreateConsole();
                printf("[%s] Loaded.\n", __DLL_PSEUDO__);
                break;
        case DLL_THREAD_ATTACH:
                break;
        case DLL_THREAD_DETACH:
                break;
        case DLL_PROCESS_DETACH:
                printf("[%s] Unloaded.\n", __DLL_PSEUDO__);
                break;
        default:
                break;
        }
        return TRUE;
}


