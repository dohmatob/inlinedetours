#include <windows.h>
#include <stdio.h>

#define __MY_NAME__ "SLEEPING-BEAUTY"

typedef void (*HOOK)(void);

HOOK hook = 0;
HMODULE hDll = 0;

int main(int argc, char *argv[])
{
	DWORD dwDuration = 25*1000;

	if (argc > 1)
	{
		printf("[%s] Loadin: %s\n", __MY_NAME__, argv[1]);
		if ((hDll = LoadLibraryA(argv[1])))
		{
			printf("[%s] OK (DLL loaded /@0x%08X).\n", __MY_NAME__, (int)hDll);
			printf("[%s] Resolving %s!HookSleepEX API ..\n", __MY_NAME__, argv[1]);
			if (!(hook = (HOOK)GetProcAddress(GetModuleHandleA(argv[1]), "HookSleepEx")))
			{
				printf("[%s] Warning: couldn't resolve %s!HookSleepEx\n", __MY_NAME__, argv[1]);
			}
			else
			{
				printf("[%s] OK (API resolved /@0x%08X).\n", __MY_NAME__, (int)hook);
				printf("[%s] Invoking HookSleepEx() ..\n", __MY_NAME__);
				hook();
				printf("[%s] OK (API invoked).\n", __MY_NAME__);
			}
		}
		else
		{
			printf("[%s] Warning: couldn't load %s\n.\n", __MY_NAME__, argv[1]);
		}
	}
	if (argc > 2)
	{
		dwDuration = atoi(argv[2])*1000;
	}

	printf("[%s] Sleep-ing %d milliseconds.\n", __MY_NAME__, dwDuration);
	Sleep(dwDuration);
	printf("[%s] Done.\n",__MY_NAME__);
	printf("[%s] SleepEx-ing %d milliseconds.\n", __MY_NAME__, dwDuration + 1000);
	SleepEx(dwDuration + 1000, 0);
	printf("[%s] Done.\n", __MY_NAME__);
	
	printf("[%s] Unloadin: %s\n", __MY_NAME__, argv[1]);
	FreeLibrary(hDll);

	return 0;
}
