++++++++++
+ README +
++++++++++

firefoxspy v?: a tiny DLL for sniffing pre-encryption traffic from firefox.

(c) dohmatob elvis dopgima (h4lf-jiffie)

The idea is simple. Viz:
[snip]
typedef DWORD (*PR_Write_t)(void *, const void *, DWORD); // refer to https://developer.mozilla.org/en/PR_Write for doc on PR_Write
PR_Write_t g_OriginalPR_Write;

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
[snip]

BTW, sniffed data looks like this:

>>>>>>>START OF BUFFER^M
GET / HTTP/1.1^M
Host: dohmatob.blogspot.fr^M
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:11.0) Gecko/20100101 Firefox/11.0^M
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8^M
Accept-Language: en-us,en;q=0.5^M
Accept-Encoding: gzip, deflate^M
Connection: keep-alive^M
If-Modified-Since: Thu, 10 May 2012 17:20:21 GMT^M
If-None-Match: "f824ad9a-c535-4033-b9c3-3228f442b6e2"^M
^M
^M
END OF BUFFER<<<<<<<^M

-1. DISCLAIMER
++++++++++++++
This code is for educational purposes only. Don't use in production environment, or other assert. No warrantly is implied.
Use at your own risk.

0. TODO
++++++++
Implement code to do some cool things in function Sniff(..).

1. Usage
++++++++
Inject the built .dll into firefox process, and invoke HookPR_Write(). I could have put this in the exported DllMain, but I 
wanted to keep kiddies away. BTW, kiddies --surely!-- can't build this from source :).

2. Compatitibility
++++++++++++++++++
Built and tested on windows 7; should work on xp and vista too. However, you'll need MSVCR (if you don't have it installed,
you may simple copy  msvcp100.dll and msvcr100.dll from your system32 directory to your firefox installation directory).

Good-Luck.

(c) dohmatob elvis dopgima (h4lf-jiffie)



