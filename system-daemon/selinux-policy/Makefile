export PWD := $(shell pwd)
export TARGETDIR := ${PWD}/../../target/fedora

rpm: *
	@echo "Building and Loading Policy"
	set -x
	make -f /usr/share/selinux/devel/Makefile softu2f-system-daemon.pp
	rpmbuild --define "_sourcedir ${PWD}" --define "_specdir ${PWD}" --define "_builddir ${PWD}" --define "_srcrpmdir ${TARGETDIR}" --define "_rpmdir ${TARGETDIR}" --define "_buildrootdir ${PWD}/.build" -ba softu2f-system-daemon-selinux.spec

.PHONY: rpm
