ROOTDIR=..
!include "$(ROOTDIR)\system.mak"

all:
	cd $(MAKEDIR)\firefoxspy
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)\pinballspy
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd $(MAKEDIR)

clean:
	cd $(MAKEDIR)\firefoxspy
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)\pinballspy
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd $(MAKEDIR)

test:
	cd $(MAKEDIR)\firefoxspy
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) test
	cd $(MAKEDIR)


