++++++++++
+ README +
++++++++++

inlinedetours v?
(c) dohmatob elvis dopgima (h4lf-jiffie)

inlinedetours is a static library (which means the linker will link it into your client code just as if you had written 
it as part of the code) for run-time-hooking win32 APIs and arbitrary asm instruction sequences alike, on a per-process 
basis.

0. TODO
++++++++

Implement a built-in disam heuristic to automatically determine API prologs.

1. Usage
++++++++

1.0 Detouring APIs
++++++++++++++++++

To detour/hook --say-- the SleepEx API (from kernel32) in a target process X (i.e. subsequent calls to SleepEx made 
from X will be routed to a proxy, etc.), you would code the following stubs in a DLL Y (excerpt from 
testdlls\basicproxy\main.cpp):

[snip]
DWORD (WINAPI *OriginalSleepEx)(DWORD, BOOL) = SleepEx; // original SleepEx API from kernel32
[snip]

And then code the following hook (still in Y, of course!):

[snip]
void HookSleepEx(void)
{
	InstallDetour((PVOID *)&OriginalSleepEx, (PVOID)FakeSleepEx, 0x5); // as easy as that !
	printf("[%s] SleepEx api hacked! Calls to SleepEx will henceforth be routed to FakeSleepEx.\n", __DLL_PSEUDO__);
}
[snip]

where FakeSleepEx must have same prototype (including 'calling convention') as SleepEx. For example, FakeSleepEx could 
be something like:

[snip]
DWORD WINAPI FakeSleepEx(DWORD dwMiliseconds, BOOL bAlertable)
{
	DWORD dwTickCount = GetTickCount();
	DWORD dwRetVal = OriginalSleepEx(dwMiliseconds, bAlertable);
	DWORD dwDelta = GetTickCount() - dwTickCount;
	printf("[%s] Slept for %d millisenconds.\n", __DLL_PSEUDO__, dwDelta);
	return dwRetVal;
}
[snip]

You would then let X load Y (by DLL injection, etc.) and invoke HookSleepEx from it (by DLL injection, etc.).

N.B: For the moment, I have no means of automatically determining the size of a API's prolog (use a built-in 
disassembler, etc. ?), other than using a debugger (ollydbg ?). My debugger told me that SleepEx leaves in a 'jump 
table' in process X's image; and an unconditional jump is worth 0x5 bytes of opcode. This heuristic works for now, but 
is very risky. See TODO section.

1.1 Hooking arbitrary sequence of instructions
++++++++++++++++++++++++++++++++++++++++++++++

Remarque:
The key difference between an API function and an arbitrary sequence of (assembly) instructions is that the former will 
usually have a prolog and epilog for stack-housekeeping etc., while the latter is just a chunk of bytes that could be 
right in the middle of a function's body! For this reason, most (if not all) detours libraries out there simple don't 
support the latter. Plus, those libraries rely on this very prolog/epilog thing to determine what opcodes to patch-away 
when installing detours. Well, our inlinedetours library treats both scenarios thesame: you can hook just about 
anything: the only requirement is that it (the thing!) be a sequence of FULL (not TRUNCATED!) assembly instructions!

Now, consider the following from a multi-player your-turn-my-turn game, and believe it or not, at 0x010196BE, EDX holds 
the current score of the current player :):

[snip]
0x010196BA: ADD DWORD PTR DS:[EAX], ESI
0x010196BC: MOV EDX, DWORD PTR DS:[EAX]
0x010196BE: CMP EDX, 3B9ACA00 ; opcodes = \x01\x30\x8B\x10\x81\xFA\x00\xCA\x9A\x3B
0x010196C4: JLE SHORT 010196D1
0x010196B6: ADD EDX, C4653600
[snip]

Say, we wanted hook the instruction (6 bytes) at 0x010196BE and do the following pre-treatment (which simply extracts 
the current score and displays it). Then, we'd simply code the following stub in a DLL Y:

[snip excerpt from clientdlls\pinballspy\pinballspy.cpp]
void __declspec(naked) ExtractScore(void) // naked, so we have neither prolog nor epilog stuff, just payload :)
{
	__asm push dwExtractScoreRetAddr // saved return address
	__asm mov dwCurrentScore, edx // backup edx (this contains the score :))
	__asm pushad // save general registers (EAX, EBX, EDX, ..)
	__asm pushfd // save flags (EFLAGS)
	DisplayScore(); // this will corrupt the current thread's context
	__asm popfd // restore general registers
	__asm popad // restore flags
	__asm cmp edx, 0x3B9ACA00 // this 6-byte instruction was patched away by detour
	__asm ret // return like a ninja
}

void TrapScore(void)
{
	DWORD dwCmpEdxAddr = 0x010196BE; // target pointer
	InstallDetour((PVOID *)&dwCmpEdxAddr, (PVOID)ExtractScore, 0x6);
	dwExtractScoreRetAddr = dwCmpEdxAddr + 0x6; // = 0x010196C4 
}

void UntrapScore(void)
{
	DWORD dwCmpEdxAddr = dwExtractScoreRetAddr - 0x6;
	UninstallDetour((PVOID *)&dwCmpEdxAddr);
}
[snip]

We'd then make the game (X) load the DLL Y (by dll injection, etc.) and invoke TrapScore(..) to hook the instruction at 
0x010196BE or UntrapScore(..) to unhook it. Yes, it's that neat!

1.2. Real-life: Hooking closed-source/proprietary/custom APIs
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

1.2.0 Scenarion
+++++++++++++++

I need to hook the nspr4.dll!PR_Write API (see https://developer.mozilla.org/en/PR_Write) used by firefox (Windows 
version). The problem is that I don't have a the mozilla sdk (xulrunner-sdk, etc.) --or I consider it an overkill! 
Indeed, this is not fiction, as it is usually the case in real-life (ask game-hackers, etc.). 

Thus, my detour can't just be a wrapper around some OriginalFR_Write(??, ??, ??) like in the 1.0 case above  where we 
detoured the kernel32.dll!SleepEx API. Thence, in my detour --alas!-- I'll need a way to do my 'thing' and then let 
PR_Write continue it's 'thing' past the bytes patched-off by the detour installer, without wrapping around anything 
whatsoever.

1.2.1 Solution: the trick that works even in hell!
++++++++++++++++++++++++++++++++++++++++++++++++++

A detour, implemented in naked in-line assembly, with the following layout does the job neat. Viz,

Step 0: Prolog
++++++++++++++

Scrape arguments from current stack frame. Suppose the target API takes K parameters. In our detour, we can retrieve 
from its stack frame as follows:
[snip] 
	__asm mov eax, [esp + 0x4]	// first arg
	__asm mov dwArg1, eax
	__asm mov eax, [esp + 0x8]	// second arg
	__asm mov dwArg2, eax
        ..
	..
	__asm mov eax, [esp + 0x4*K]	// Kth arg
	__asm mov dwArgK, eax
[snip]

Step 1: Invoke callback logic to act on scraped arguments
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

This is quite easy. Indeed,
[snip]
	__asm pushad	// save registers
	__asm pushfd	// save eflags
	MyDetourCallback()	// This will corrupt the current stack frame
	__asm popfd	// restore eflags
	__asm popad	// restore registers
[snip]

Of course, you'll have to make the dwArg1, dwArg2, .., dwArg3 (see step 0) global variables visible to the 
MyDetourCallbackfunction.

Step 2. Epilog
++++++++++++++
[snip]
	__asm push dwMyDetourRetAddr
	__asm retn
[snip]

Where, dwMyDetourRetAddr, would've been pre-calculated before invoking InstallDetour(..) on the target API. BTW, this 
should be exactly equal to dwTargetApiAddr + dwNumberOfBytesToPatchOff. We'll see more on this in 1.2.2.

1.2.2 A concrete solution (so you see what we're saying here): nspr4.dll!PR_Write case
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The detour is ..
[snip]
void __declspec(naked) PR_WriteDetour(void)
{
	// read arguments off PR_Write's stack frame (see https://developer.mozilla.org/en/PR_Write for doc on nspr4!PR_Write's prototype)
	__asm mov eax, [esp + 0x8]	// second argumment
	__asm mov buf, eax
	__asm mov ecx, [esp + 0xC]	// third argument
	__asm mov amount, ecx

	// invoke callback logic
	__asm pushad
	__asm pushfd
	FR_WriteCallback();
	__asm popfd
	__asm popad

	// the following instructions where patched-off; bring them in
	__asm mov eax, DWORD PTR SS:[esp + 0x4]
	__asm mov ecx, DWORD PTR DS:[eax]

	// quit
	__asm push dwPR_WriteDetourRetAddr
	__asm retn
}
[snip]

.. and would be installed by ..
[snip]
void HookPR_Write(void)
{
	[snip]
	dwPR_WriteDetourRetAddr = dwPR_WriteAddr + 0x6;
	InstallDetour((PVOID *)&dwPR_WriteAddr, (PVOID)PR_WriteDetour, 0x6);
	[snip]
}
[snip]

Remarque: For the complete solution in context, please refer to https://github.com/half-jiffie/firefoxspy.

2.0 Technique: How does inlinedetours work?
+++++++++++++++++++++++++++++++++++++++++++

Invoking InstallDetour((PVOID *)&pTarget, PVOID pDetour, DWORD dwOriginalOpcodes) is intended to install a detour of size
dwOriginalOpcodes bytes at pTarget. Subsequent calls/references to pTarget will be routed to the detour 
pointed-to by pDetour. The lib achieves this as follows (type casts, error-checking, and thread-safety stripped):

0) initialze .. (allocate codecaves, tweak virtual memory protections, etc.)

1) copy first dwOriginalOpcodes bytes starting at pTarget to a 'safe place in memory', preceeded by a 'jump 5 bytes 
ahead'; this 'backup' is technically refered to as a 'detour' (because, to invoke the original instructions, we'd 
simply 'jump to that place'. 
In summary: detour = 'jmp to origin' + origin
This leaves a dwOriginalOpcodes-byte codecave starting at pTarget. BTW, a detour structure looks as follows 
(excerpt from inlinedetours.h):

[snip]
struct detour_struct
{
	PVOID pTarget;               // pointer to target function or instruction block
	PVOID pDetour;               // pointer to detour function or instruction block
	DWORD dwOriginalOpcodes; // number of bytes to be detoured from the start of target function, or size of ..
				 // .. target block 
	PBYTE pTrampoline2Target;           // pointer to instruction block which re-routes to the original/undetoured function or instruction 									 // ..block
	detour_struct(PVOID _pTarget, PVOID _pDetour, DWORD _dwOriginalOpcodes)
	{
		pTarget = _pTarget;
		pDetour = _pDetour;
		dwOriginalOpcodes = _dwOriginalOpcodes;
	}
} 
[snip]

N.B.:- the detour  (this is abuse of language; I really mean, detour->pTrampoline2Target) is 5 + dwOriginalOpcodes 
bytes long, and its last dwOriginalOpcodes bytes are exactly the bytes copied from pTarget (you see how we would unhook 
a detour?).

2) write a NOP-sled of length dwOriginalOpcodes - 5 at pTarget (this leaves a 5-byte codecave for a long jump)

3) write a 'jump to pDetour' at pTarget + dwOriginalOpcodes - 5 (this completes the dwOriginalOpcodes codecave)

4) set *(&pTarget) = detour (this way, we can re-route to the original opcodes if we so wished!)

5) There is no 5. That's it!

Remarque: Observe that point 4) above provides for a function trap/proxy of the form 'target -> prehandler + target + 
posthandler'.

A dictionary of all detour structures (see the g_detours linked-list varibale in inlinedetours\inlinedetours.h) is 
maintained so detours can be subsequenty undone.


Likewise, invoking UninstallDetour((PVOID *)&pTarget) is intended to undo a previous installed detour (i.e re-route the
original opcodes of the target). This is done back-end by the lib as follows:

1) search for a detour with key = pTarget (if this search fails, then we're trying to undo a detour that was never 
installed in the first place!)

0) initialize ..

2) restoration: copy the last detour->dwOriginalOpcodes bytes of detour->pTrampoline2Target to pTarget


3. Compatibility
++++++++++++++++

Should work on XP or later.


(c) h4lf-jiffie (dohmatob elvis dopgima)
    17 January 2012, Pessac (France)

// E.O.F.
