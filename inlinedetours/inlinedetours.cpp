//////////////////////////////////////////////
// (c) dohmatob elvis dopgima (h4lf-jiffie)
/////////////////////////////////////////////

#include "stdafx.h"
#include "inlinedetours.h"

// GLOBALS
static std::vector<detour_t> g_detours;
static std::vector<HANDLE> g_suspendedThreads;
static CRITICAL_SECTION g_csCriticalCodeSection;
static BOOL g_csCriticalCodeSectionInitialized = false;

/////////////////////////////////////////////////////////////////////
// Function will attempt to find given signature in process memory
/////////////////////////////////////////////////////////////////////
void FindSignatureInProcessMemory(HANDLE hProcess, PBYTE pSignature, DWORD dwSignature, std::vector<unsigned long>& hits, \
	BAD_MBI_FILTER BadMbiFilter)
{
	// local variables
	MEMORY_BASIC_INFORMATION mbi;
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	DWORD dwStartOffset = (DWORD)si.lpMinimumApplicationAddress;
	DWORD dwOldProtection;
	DWORD dwBytesRead;
	PBYTE pTmpBuf;
	DWORD dwBlockOffset;
	DWORD i;
	BOOL bSkipRegion;

	// allocate temporary buffer
	if (!(pTmpBuf = (PBYTE)malloc(si.dwPageSize)))
	{
		printf("[%s] Error: malloc (GetLastError() = 0x%08X).\n", __LIB_PSEUDO__, GetLastError());
		return;
	}

	// scrape process vritual memory
	printf("[%s] Searching for signature '%s' in process memory ..\n", __LIB_PSEUDO__, pSignature);
	while (dwStartOffset < (DWORD)si.lpMaximumApplicationAddress)
	{
		// scrape memory block from dwStartOffset through dwStartOffset + mbi.RegionSize, in si.dwPageSize-byte chunks
		// (my assumption is that mbi.RegionSize is always a multiple of of si.dwPageSize --No?)
		VirtualQueryEx(hProcess, (LPVOID)dwStartOffset, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		bSkipRegion = false; // don't skip this region
		if (BadMbiFilter)
		{
			// caller specified some addition criteria
			bSkipRegion = BadMbiFilter(mbi);
		}

		// XXX default criteria
		bSkipRegion = bSkipRegion || (mbi.State != MEM_COMMIT); // bring-in State filter
		bSkipRegion = bSkipRegion || ((mbi.Type != MEM_IMAGE) && (mbi.Type != MEM_MAPPED)); // bring-in Type filter
		if (bSkipRegion)
		{
			dwStartOffset += mbi.RegionSize;
			continue;
		}

		dwBlockOffset = dwStartOffset;
		for (; dwBlockOffset < dwStartOffset + mbi.RegionSize; dwBlockOffset += si.dwPageSize)
		{
			// printf("[%s] scraping region 0x%08X - 0x%08X ..\n", __LIB_PSEUDO__, dwBlockOffset, dwBlockOffset + si.dwPageSize);
			if (!VirtualProtectEx(hProcess, (LPVOID)dwBlockOffset, si.dwPageSize, PAGE_READWRITE, &dwOldProtection))
			{
				continue;
			}

			if (!(ReadProcessMemory(hProcess, (LPCVOID)dwBlockOffset, pTmpBuf, si.dwPageSize, &dwBytesRead) ? true : \
				(dwBytesRead == si.dwPageSize)))
			{
				printf("[%s] Error: ReadProcessMemory: Can't read 0x%08X + %d (GetLastError() = 0x%08X).\n", __LIB_PSEUDO__, \
						dwBlockOffset, si.dwPageSize, GetLastError());
				VirtualProtectEx(hProcess, (LPVOID)dwBlockOffset, si.dwPageSize, dwOldProtection, &dwOldProtection);
				continue;
			}

			VirtualProtectEx(hProcess, (LPVOID)dwBlockOffset, si.dwPageSize, dwOldProtection, &dwOldProtection);
			// Is pSignature a sub-string of pTmpBuf? Where?
			for (i = 0; i + dwSignature - 1 < si.dwPageSize; i++)
			{
				if(!memcmp(pTmpBuf + i, pSignature, dwSignature))
				{
					printf("[%s] Found '%s' at 0x%08X (mbi.State = 0x%08X, mbi.Protect = 0x%08X, mbi.Type = 0x%08X).\n", __LIB_PSEUDO__,\
							pSignature, i + dwBlockOffset, mbi.State, mbi.Protect, mbi.Type);
					hits.push_back(i + dwBlockOffset); // store new result
				}
			} // end 'for i'
		} // end 'for dwBlockOffset'
		dwStartOffset += mbi.RegionSize; // progress one memory block forward
	} // end 'while'
	printf("[%s] OK (found %d occurrences).\n", __LIB_PSEUDO__, hits.size());
	delete []pTmpBuf;
	CloseHandle(hProcess);
	return;
}

////////////////////////////////////////////////////////////////////////////////////////
// Function generates a jump from dwSrcAddr to dwDstAddr; the jump is written to pBuf
///////////////////////////////////////////////////////////////////////////////////////
void MakeJmp(DWORD dwSrcAddr, DWORD dwDstAddr, PBYTE pBuf)
{
	DWORD dwOffset = dwDstAddr - dwSrcAddr - 5; // an unconditional jump instruction is worth 5 bytes of opcode
	*pBuf = 0xE9;
	memcpy(pBuf + 1, &dwOffset, 4);
}

///////////////////////////////////////////////////////////////////////////////////////////////
// Invoked by current thread in current process to suspend all other threads of the process
//////////////////////////////////////////////////////////////////////////////////////////////
BOOL SuspendAllOtherThreads(void)
{
	// local variables
	int oldPriority = GetThreadPriority(GetCurrentThread());
	THREADENTRY32 te32;
	HANDLE hSnapshot;
	HANDLE hThread;
	te32.dwSize = sizeof(THREADENTRY32);

	// serious business here, please!
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	printf("[%s] Suspending all other threads ..\n", __LIB_PSEUDO__);

	// snap system threads
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == INVALID_HANDLE_VALUE)
	{
		printf("[%s] Error: CreateToolhelp32Snapshot: couldn't take snapshot of system threads (GetLastError() = 0x%08X).\n", \
				GetLastError());
		SetThreadPriority(GetCurrentThread(), oldPriority); // restore original thread priority
		return false;
	}

	// walk system threads, trying to suspend those that belong to this process
	if (Thread32First(hSnapshot, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
			{
				printf("[%s] Suspending thread %d ..\n", __LIB_PSEUDO__, te32.th32ThreadID);
				if (!(hThread = OpenThread(THREAD_SUSPEND_RESUME, 0, te32.th32ThreadID)))
				{
					printf("[%s] Error: OpenThread: couldn't open thread (GetLastError() = 0x%08X).\n", __LIB_PSEUDO__, GetLastError());
					continue;
				}
				printf("[%s] OK.\n", __LIB_PSEUDO__);
				SuspendThread(hThread); /// XXX TODO: error-checking (this may fail --No?)
				g_suspendedThreads.push_back(hThread);
			}
		} while (Thread32Next(hSnapshot, &te32));
		printf("[%s] OK (suspended %d threads).\n", __LIB_PSEUDO__, g_suspendedThreads.size());
		SetThreadPriority(GetCurrentThread(), oldPriority); // restore original thread priority
		return true;
	}
	else
	{
		printf("Error: Thread32First: failed (GetLastError() = 0x%08X).\n", __LIB_PSEUDO__, GetLastError());
		SetThreadPriority(GetCurrentThread(), oldPriority); // restore original thread priority
		return false;
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Invoked by current thread to resume all threads suspended by an earlier call to SuspsendAllOtherThreads(..)
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL ResumeAllOtherThreads(void)
{
	// local variables
	DWORD dwResumedThreads = 0;
	DWORD dwSuspendedThreads = g_suspendedThreads.size();
	int oldPriority = GetThreadPriority(GetCurrentThread());

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL); // we are in some serious business here, please!
	printf("[%s] Resuming all other threads ..\n", __LIB_PSEUDO__, dwSuspendedThreads);

	// traverse list of suspended threads, try resuming them as you go along
	for(std::vector<HANDLE>::iterator thi = g_suspendedThreads.begin(); thi != g_suspendedThreads.end(); thi++)
	{
		ResumeThread(*thi);
		CloseHandle(*thi);
		dwResumedThreads++;
	}
	if (dwResumedThreads < dwSuspendedThreads)
	{
		printf("[%s] Warning: ResumeAllOtherThreads: resumed %d threads of %d suspended.\n", __LIB_PSEUDO__, dwResumedThreads, \
				dwSuspendedThreads);
	}
	else
	{
		printf("[%s] OK (resumed %d threads).\n", __LIB_PSEUDO__, dwSuspendedThreads);
	}

	// sanity
	g_suspendedThreads.clear();
	SetThreadPriority(GetCurrentThread(), oldPriority);
	return dwResumedThreads == dwSuspendedThreads;
}

PVOID AllocateCodecave(DWORD dwSize)
{
	// XXX Use better heuristic
	return VirtualAllocEx(GetCurrentProcess(), 0, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Tries to uninstall a previously installed detour (thereby re-routing the target to its original opcodes)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD UninstallDetour(PVOID *ppTarget)
{
	// local variables
	DWORD protection;	// memory protection

	// initialize ..
	if (!g_csCriticalCodeSectionInitialized)
	{
		InitializeCriticalSection(&g_csCriticalCodeSection);
		g_csCriticalCodeSectionInitialized = true;
	}

	EnterCriticalSection(&g_csCriticalCodeSection);

	printf("[%s] Uninstalling detour ..\n", __LIB_PSEUDO__);

	// suspend all other threads; we run this thing!
	SuspendAllOtherThreads();

	printf("[%s] Searching for detour structure verifying \`detour->pTrampoline2Target == 0x%08X\`.\n", \
			__LIB_PSEUDO__, (DWORD)*ppTarget);

	// search corresponding detour, and then undo detour
	for(std::vector<detour_t>::iterator detour = g_detours.begin(); detour != g_detours.end(); detour++)
	{
		if (detour->pTrampoline2Target == *ppTarget)
		{
			// we got a hit; do housekeeping
			printf("[%s] Found detour: dwOriginalOpcodes = %d, pDetour = 0x%08X, pTarget = 0x%08X.\n", __LIB_PSEUDO__, \
					detour->dwOriginalOpcodes, (DWORD)(detour->pDetour), (DWORD)detour->pTarget);
			printf("[%s] Changing protection on virtual region 0x%08X - 0x%08X.\n", __LIB_PSEUDO__, (DWORD)detour->pTarget, \
					(DWORD)detour->pTarget + detour->dwOriginalOpcodes);
			if(!VirtualProtect(detour->pTarget, detour->dwOriginalOpcodes, PAGE_EXECUTE_READWRITE, &protection))
			{
				printf("[%s] VirtualProtect: Can't change protection on virtual region 0x%08X - 0x%08X (GetLastError() = 0x%08X).\n", \
						__LIB_PSEUDO__, (DWORD)detour->pTarget, (DWORD)detour->pTarget + detour->dwOriginalOpcodes, \
						GetLastError());
				ResumeAllOtherThreads(); // resume all the other threads
				LeaveCriticalSection(&g_csCriticalCodeSection); // leave critical section
				return DETOUR_ERROR_PAGE_PROTECTION; // report error
			}
			printf("[%s] OK (protection changed to PAGE_EXECUTE_READWRITE).\n", __LIB_PSEUDO__);
			printf("[%s] Restoring target original opcodes at 0x%08X.\n", __LIB_PSEUDO__, detour->pTarget);
			memcpy(detour->pTarget, detour->pTrampoline2Target, detour->dwOriginalOpcodes); // restore patched-off bytes
			printf("[%s] OK (restored %d-byte code-block).\n", __LIB_PSEUDO__, detour->dwOriginalOpcodes);
			*ppTarget = detour->pTarget; // re-route target to its original opcodes
			FlushInstructionCache(GetCurrentProcess(), detour->pTarget, detour->dwOriginalOpcodes); // make changes asap
			printf("[%s] Restoring protection on target memory.\n", __LIB_PSEUDO__);
			VirtualProtect(detour->pTarget, detour->dwOriginalOpcodes, protection, &protection);
			printf("[%s] OK (protection restored)\n", __LIB_PSEUDO__);
			ResumeAllOtherThreads(); // resume all the other threads
			printf("[%s] OK (uninstalled detour at 0x%08X).\n", __LIB_PSEUDO__, detour->pTarget);
			// g_detours.erase(detour); // delete detour from household
			LeaveCriticalSection(&g_csCriticalCodeSection); // leave critical section
			return DETOUR_NOERROR; // OK
		}
	}

	// if we're here, then we screwed!
	printf("[%s] Error: Couldn't find corresponding detour structure.\n", __LIB_PSEUDO__);
	ResumeAllOtherThreads(); // resume all the other threads of this process
	LeaveCriticalSection(&g_csCriticalCodeSection); // leave critical section
	return DETOUR_ERROR_NONEXISTENT_TRANSACTION; // report error
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Installs a detour on a target, thereby re-directing subsequent calls/references to the target, to the detour
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD InstallDetour(PVOID *ppTarget, PVOID pDetour, DWORD dwOriginalOpcodes)
{
	// local variables
	detour_t *detour;	// will encapsulate target, detour, plus detour data
	DWORD protection;			// memory protection

	// initialize ..
	if (!g_csCriticalCodeSectionInitialized)
	{
		InitializeCriticalSection(&g_csCriticalCodeSection);
		g_csCriticalCodeSectionInitialized = true;
	}

	// enter critical section; code that follows must be executed thread-safely !
	EnterCriticalSection(&g_csCriticalCodeSection);

	printf("[%s] Installing %d-byte detour on target at 0x%08X (current thread ID = %d).\n", __LIB_PSEUDO__, dwOriginalOpcodes, \
		(DWORD)*ppTarget, GetCurrentThreadId());

	// thread-safety: suspend all threads first!
	SuspendAllOtherThreads();

	// verify that no other detoured pointer lies withing dwOriginalOpcodes bytes of the target *pTarget
	printf("[%s] Making sure this detour doesn't override an earlier detour ..\n", __LIB_PSEUDO__);
	for(std::vector<detour_t>::iterator detour = g_detours.begin(); detour != g_detours.end(); detour++)
	{
		if ((unsigned long)abs((long)((unsigned long)detour->pTarget - (unsigned long)*ppTarget)) < (unsigned long)dwOriginalOpcodes)
		{
			printf("[%s] Error: InstallDetour: this detour would override an existing placed at 0x%08X; operation has been cancelled.\n",\
					__LIB_PSEUDO__, detour->pTarget);
			ResumeAllOtherThreads();
			LeaveCriticalSection(&g_csCriticalCodeSection);
			return DETOUR_ERROR_INVALID_OPERATION;
		}
	}
	printf("[%s] OK.\n", __LIB_PSEUDO__);

	// need at least 5-bytes worth of code-cave to do business, please!
	printf("[%s] Making sure cave isn't too small.\n", __LIB_PSEUDO__);
	if (dwOriginalOpcodes < 5)
	{
		printf("[%s] Error: Cave too small; need at least 5-byte to insert unconduictional jump.\n", __LIB_PSEUDO__);
		LeaveCriticalSection(&g_csCriticalCodeSection);
		return DETOUR_ERROR_CAVE_TOOSMALL;
	}
	printf("[%s] OK.\n", __LIB_PSEUDO__);

	// protection tweaking
	printf("[%s] Changing protection on virtual region 0x%08X - 0x%08X.\n", __LIB_PSEUDO__, (DWORD)*ppTarget, (DWORD)*ppTarget + \
		dwOriginalOpcodes);
	if(!VirtualProtect(*ppTarget, dwOriginalOpcodes, PAGE_EXECUTE_READWRITE, &protection))
	{
		printf("[%s] Error: VirtualProtect: Can't change protection on virtual region 0x%08X - 0x%08X (GetLastError() = 0x%08X).\n", \
				__LIB_PSEUDO__, \
			(DWORD)*ppTarget, (DWORD)*ppTarget + dwOriginalOpcodes, GetLastError());
		ResumeAllOtherThreads();
		LeaveCriticalSection(&g_csCriticalCodeSection);
		return DETOUR_ERROR_PAGE_PROTECTION;
	}
	printf("[%s] OK (protection changed to PAGE_EXECUTE_READWRITE).\n", __LIB_PSEUDO__);

	// installation proper
	printf("[%s] Initializing detour.\n", __LIB_PSEUDO__);
	if (!(detour = new detour_t(*ppTarget, pDetour, dwOriginalOpcodes)))
	{
		printf("[%s] Error: Couldn't initialize detour.\n", __LIB_PSEUDO__);
		ResumeAllOtherThreads();
		LeaveCriticalSection(&g_csCriticalCodeSection);
		return DETOUR_ERROR_NO_MEMORY;
	}
	printf("[%s] OK.\n", __LIB_PSEUDO__);
	printf("[%s] Allocating detour's trampoline for target restoration ..\n", __LIB_PSEUDO__);
	if (!(detour->pTrampoline2Target = (PBYTE)AllocateCodecave(dwOriginalOpcodes + 5)))
	{
		printf("[%s] Error: AllocateCodecave: Can't allocated memory for detour (GetLastError() = 0x%08X).\n", __LIB_PSEUDO__, \
				GetLastError());
		VirtualProtect(*ppTarget, dwOriginalOpcodes, protection, &protection);
		ResumeAllOtherThreads();
		LeaveCriticalSection(&g_csCriticalCodeSection);
		return DETOUR_ERROR_NO_MEMORY;
	}
	printf("[%s] OK (%d-btye READ_EXECUTE_READWRITE block allocated at 0x%08X).\n", __LIB_PSEUDO__, dwOriginalOpcodes, \
			detour->pTrampoline2Target);

	printf("[%s] Building detour ..\n", __LIB_PSEUDO__);

	// backup target's first dwOriginalOpcodes to detour's pTrampoline2Target buffer
	printf("\t\t\tBacking up first %d bytes of target to detour's trampoline ..\n", dwOriginalOpcodes);
	memcpy(detour->pTrampoline2Target, *ppTarget, dwOriginalOpcodes);
	MakeJmp((DWORD)detour->pTrampoline2Target + dwOriginalOpcodes, (DWORD)detour->pTarget + dwOriginalOpcodes, \
			detour->pTrampoline2Target + dwOriginalOpcodes);
	FlushInstructionCache(GetCurrentProcess(), detour->pTrampoline2Target, dwOriginalOpcodes + 5);
	printf("\t\t\tOK.\n");

	// patch target with jmp
	printf("\t\t\tWriting patch to target ..\n");
	memset(*ppTarget, 0x90, dwOriginalOpcodes - 5); // NOP-sled
	MakeJmp((DWORD)*ppTarget + dwOriginalOpcodes - 5, (DWORD)pDetour, (PBYTE)*ppTarget + dwOriginalOpcodes - 5);
	FlushInstructionCache(GetCurrentProcess(), *ppTarget, dwOriginalOpcodes);
	printf("\t\t\tOK (%d-byte patch writen to target at 0x%08X).\n", dwOriginalOpcodes, (DWORD)detour->pTarget);

	// setup restoration stub
	*ppTarget = detour->pTrampoline2Target; // so we can undo the detour later
	printf("[%s] OK (detour built: detour->pTarget=0x%08X, tramopline->dwOriginalOpcodes=%d, detour->pDetour=0x%08X, "
			"detour->pTrampoline2Target=0x%08X).\n", __LIB_PSEUDO__, (DWORD)detour->pTarget, detour->dwOriginalOpcodes, \
			(DWORD)detour->pDetour, (DWORD)detour->pTrampoline2Target);

	// register new detour
	g_detours.push_back(*detour);

	// restore memory protection tweaked earlier
	printf("[%s] Restoring protection on target memory.\n", __LIB_PSEUDO__);
	VirtualProtect(*ppTarget, dwOriginalOpcodes, protection, &protection);
	printf("[%s] OK (protection restored)\n", __LIB_PSEUDO__);

	// finish
	ResumeAllOtherThreads();
	LeaveCriticalSection(&g_csCriticalCodeSection);
	printf("[%s] OK (installation complete).\n", __LIB_PSEUDO__);
	return DETOUR_NOERROR;
}



