ROOTDIR=..\..

!include "$(ROOTDIR)\clientdlls\common.mak"

all: $(BINDIR)\pinballspy.dll clean

$(BINDIR)\pinballspy.dll $(LIBDIR)\pinballspy.lib: pinballspy.obj dllmain.obj $(DEPENDENCIES)
     	$(CC) /LD $(CFLAGS) /Fe$@ /Fd$(BINDIR)\pinballspy.pdb \
        pinballspy.obj dllmain.obj \
        /link $(LINKFLAGS) /incremental:no /subsystem:console \
	/entry:$(DLLENTRY) \
	/export:DllMain \
        /export:TrapScore \
	/export:UntrapScore \
        $(LIBRARIES)

clean:	
	-del /Q *.obj 2>null # XXX quick-dirty-hack!

