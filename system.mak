OBJDIR=$(ROOTDIR)\obj
LIBDIR=$(ROOTDIR)\lib
BINDIR=$(ROOTDIR)\bin
INCDIR=$(ROOTDIR)\inlinedetours

LINKFLAGS=/Debug

.cpp{$(OBJDIR)}.obj:
	$(CC) /nologo $(CFLAGS) /Fo$@ /c .\$(*B).cpp
