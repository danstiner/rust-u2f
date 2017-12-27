export PWD := $(shell pwd)

softu2f_systemd_daemon.pp: *
	@echo "Building and Loading Policy"
	set -x
	make -f /usr/share/selinux/devel/Makefile softu2f-systemd-daemon.pp
	rpmbuild --define "_sourcedir ${PWD}" --define "_specdir ${PWD}" --define "_builddir ${PWD}" --define "_srcrpmdir ${PWD}" --define "_rpmdir ${PWD}" --define "_buildrootdir ${PWD}/.build" -ba softu2f-systemd-daemon-selinux.spec
