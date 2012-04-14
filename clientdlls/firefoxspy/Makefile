ROOTDIR=..\..

!include "$(ROOTDIR)\clientdlls\common.mak"

all: $(BINDIR)\firefoxspy.dll clean

$(BINDIR)\firefoxspy.dll $(LIBDIR)\firefoxspy.lib: firefoxspy.obj dllmain.obj $(DEPENDENCIES)
     	$(CC) /LD $(CFLAGS) /Fe$@ /Fd$(BINDIR)\firefoxspy.pdb \
        firefoxspy.obj dllmain.obj \
        /link $(LINKFLAGS) /incremental:no /subsystem:console \
	/entry:$(DLLENTRY) \
	/export:DllMain \
        /export:HookPR_Write \
	/export:UnhookPR_Write \
        $(LIBRARIES)

clean:	
	-del /Q *.obj 2>null # XXX quick-dirty-hack!

