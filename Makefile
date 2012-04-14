!include "system.mak"

all:
	cd $(MAKEDIR)\inlinedetours
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)\testapplis"
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)\testdlls"
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)\clientdlls
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)

clean:
	cd $(MAKEDIR)\testapplis"
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)\testdlls"
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)\inlinedetours
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)\clientdlls
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)

test:
	cd $(MAKEDIR)\testdlls"
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) test
	cd $(MAKEDIR)


