ROOTDIR=..
!include "$(ROOTDIR)\system.mak"

CFLAGS=$(CFLAGS) /D_WIN32_WINNT=0x501 # XP or later

INCLUDES=

.cpp.exe:
	$(CC) /nologo $(CFLAGS) $(INCLUDES) /EHsc $(*B).cpp


