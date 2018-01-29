export PWD := $(shell pwd)
export TARGETDIR := ${PWD}/target/fedora

all:

user-daemon system-daemon:
	@$(MAKE) -C $@

rpm: softu2f.spec user-daemon system-daemon
	rpmbuild --define "_sourcedir ${PWD}" --define "_specdir ${PWD}" --define "_builddir ${PWD}" --define "_srcrpmdir ${TARGETDIR}" --define "_rpmdir ${TARGETDIR}" --define "_buildrootdir ${PWD}/.build" -ba softu2f.spec

.PHONY: user-daemon system-daemon rpm
