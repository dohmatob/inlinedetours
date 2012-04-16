ROOTDIR=.
!include "$(ROOTDIR)\system.mak"

all: 
	cd $(MAKEDIR)\inlinedetours
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)\testapplis
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)\testdlls
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)\clientdlls
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)
	@echo +++++[ Build complete; check the $(BINDIR) and $(LIBDIR) folders ]+++++

clean:
	cd $(MAKEDIR)\testapplis
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)\testdlls
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)\inlinedetours
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)\clientdlls
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)

test: all
	cd $(MAKEDIR)\testdlls
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) test
	cd $(MAKEDIR)


