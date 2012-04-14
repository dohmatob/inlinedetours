ROOT=..\..
!include "$(ROOT)\system.mak"

CFLAGS=/DWIN32_LEAN_AND_MEAN # strip-off junk windows headers and co.
CFLAGS=$(CFLAGS) /D_WIN32_WINNT=0x501 # XP or later

DLLENTRY=_DllMainCRTStartup@12

INCLUDES=/I $(ROOTDIR)\inlinedetours
LIBRARIES=$(LIBDIR)\inlinedetours.lib 
DEPENDENCIES=$(LIBDIR)\inlinedetours.lib

.cpp.obj:
	$(CC) /nologo $(CFLAGS) $(INCLUDES) /c $(*B).cpp
