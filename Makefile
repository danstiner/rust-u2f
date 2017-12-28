export PWD := $(shell pwd)

all:

user-daemon system-daemon:
	@$(MAKE) -C $@

rpm: softu2f.spec user-daemon system-daemon
	rpmbuild --define "_sourcedir ${PWD}" --define "_specdir ${PWD}" --define "_builddir ${PWD}" --define "_srcrpmdir ${PWD}/target" --define "_rpmdir ${PWD}/target" --define "_buildrootdir ${PWD}/.build" -ba softu2f.spec

.PHONY: user-daemon system-daemon rpm
