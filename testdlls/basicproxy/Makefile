ROOTDIR=..\..
!include $(ROOTDIR)\testdlls\common.mak

TESTEXECUTABLES=$(BINDIR)\sleepingbeauty.exe

all: $(BINDIR)\basicproxy.dll clean

$(BINDIR)\basicproxy.dll $(LIBDIR)\basicproxy.lib: main.obj $(DEPENDENCIES)
     	$(CC) /LD $(CFLAGS) /Fe$@ /Fd$(BINDIR)\basicproxy.pdb \
        main.obj \
        /link $(LINKFLAGS) /incremental:no /subsystem:console \
	/entry:$(DLLENTRY) \
	/export:DllMain \
        /export:HookSleepEx \
	/export:UnhookSleepEx \
        $(LIBRARIES)

test: all $(TESTEXECUTABLES)
	@echo +++++ -[ testing sleepingbeauty ]- +++++
	$(BINDIR)\sleepingbeauty.exe $(BINDIR)\basicproxy.dll 5
	
clean:	
	-del /Q *.obj 2>null # XXX quick-dirty-hack!

