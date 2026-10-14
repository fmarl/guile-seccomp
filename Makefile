check:
	LD_LIBRARY_PATH="$$GUIX_ENVIRONMENT/lib" guile -L src tests/seccomp.scm
