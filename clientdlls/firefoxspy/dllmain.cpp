//////////////////////////////////////////////
// (c) h4lf-jiffie (dohmatob elvis dopgima)
//     07/02/2012 Pessac - France
/////////////////////////////////////////////

#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateConsole(__DLL_PSEUDO__);
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

