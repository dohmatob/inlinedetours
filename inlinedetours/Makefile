# (c) dohmatob elvis dopgima (h4lf-jiffie)

ROOTDIR=..
!include "$(ROOTDIR)\system.mak"

CFLAGS=$(CFLAGS) /DWIN32_LEAN_AND_MEAN # strip-off junk windows headers and co.
CFLAGS=$(CFLAGS) /D_WIN32_WINNT=0x501 # XP or later

LIBFLAGS=/nologo

OBJECTS=$(OBJDIR)\inlinedetours.obj 

all: clean dirs \
	$(LIBDIR)\inlinedetours.lib \

$(LIBDIR)\inlinedetours.obj: inlinedetours.cpp inlinedetours.h 

$(LIBDIR)\inlinedetours.lib: $(OBJECTS)
	lib $(LIBFLAGS) /out:$@ $(OBJECTS) 

dirs:
	if not exist "$(OBJDIR)" mkdir "$(OBJDIR)"
	if not exist "$(LIBDIR)" mkdir "$(LIBDIR)"
	if not exist "$(BINDIR)" mkdir "$(BINDIR)

clean: # XXX BUG: the following commands still leave the build directories (obj, lib, bin, etc.); we remove them
	if exist "$(OBJDIR)" del /Q /S $(OBJDIR)
	if exist "$(LIBDIR)" del /Q /S $(LIBDIR)
	if exist "$(BINDIR)" del /Q /S $(BINDIR)

