///////////////////////////////////////////
// (c) d0hm4t06 3. d0p91m4 (h4lf-jiffie)
//////////////////////////////////////////

#include "main.h"
#include "inlinedetours.h"

typedef DWORD (WINAPI *SleepEx_t)(DWORD, BOOL);

SleepEx_t g_OriginalSleepEx;

//////////////////////////////////////////////
// Creates console if process is GUI, etc.
/////////////////////////////////////////////
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

/////////////////////////////////////////////////////////////////
// This hook is triggered whenever the SleepEx API is invoked
////////////////////////////////////////////////////////////////
DWORD WINAPI SleepExDetour(DWORD dwMilliseconds, BOOL bAlertable)
{
	printf("[%s] SleepEx(%d, %d) invoked.\r\n", __DLL_PSEUDO__, dwMilliseconds, bAlertable);
	return g_OriginalSleepEx(dwMilliseconds, bAlertable);
}

///////////////////////////////////////////////////
// Installs SleepExDetour detour on SleepEx API
//////////////////////////////////////////////////
void UnhookSleepEx(void)
{
	UninstallDetour((PVOID *)&g_OriginalSleepEx); // yeah, that easy --urhf!
}

/////////////////////////////////////////////////////
// Uninstalls SleepExDetour detour on SleepEx API
////////////////////////////////////////////////////
void HookSleepEx(void)
{
	// obtain address of kernel32.dll!SleepEx API
	if (!(g_OriginalSleepEx = (SleepEx_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SleepEx")))
	{
		printf("[%s] Error: couldn't resolve kernel32.dll!SleepEx.\n", __DLL_PSEUDO__);
		return;
	}

	// my (manual!) disassembler tells me it's 'safe' to patch-off the top 6 bytes
	InstallDetour((PVOID *)&g_OriginalSleepEx, (PVOID)SleepExDetour, 0x6); // as easy as that !
	printf("[%s] SleepEx API detoured! Calls to SleepEx will henceforth be routed to SleepExDetour.\n", __DLL_PSEUDO__);
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
