GUILE ?= guile

ifdef GUIX_ENVIRONMENT
export LD_LIBRARY_PATH := $(GUIX_ENVIRONMENT)/lib$(if $(LD_LIBRARY_PATH),:$(LD_LIBRARY_PATH))
endif

.PHONY: check
check:
	$(GUILE) -L src tests/seccomp.scm
