++++++++++
+ README +
++++++++++

(c) h4lf-jiffie (dohmatib elvis dopgima)

A dll to spy on MS 3D Pinball sessions (display current score, etc.). 

It uses the inlinedetours library (see github). 

The idea is simple: look for the signature \x01\x30\x8B\x10\x81\xFA\x00\xCA\x9A\x3B in pinball process memory and install the 
following score-extracting hook at an offset of 4 bytes beyong the address (ie., where the "\x81\xFA\x00\xCA\x9A\x3B' lives):
[snip]
void __declspec(naked) ExtractScore(void)
{
	// backup edx (this contains the score :))
	__asm mov dwCurrentScore, edx 

	// invoke callback logic
	__asm pushad // save registers
	__asm pushfd // save eflags
	DisplayScore(); // this will corrupt the current thread's context
	__asm popfd // restore registers
	__asm popad // restore eflags

	// this 6-byte instruction was patched away, bring it in once more
	__asm cmp edx, 0x3B9ACA00 

	// quit
	__asm push dwExtractScoreRetAddr // dwCmpEdxdAddr + 0x4 + 0x6
	__asm ret // return like a ninja
}
[snip]


Compile and link (build) with visual studio, etc.