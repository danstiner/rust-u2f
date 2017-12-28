export PWD := $(shell pwd)
export TARGETDIR := ${PWD}/../target/fedora

rpm: selinux-policy
	rpmbuild --define "_sourcedir ${PWD}" --define "_specdir ${PWD}" --define "_builddir ${PWD}" --define "_srcrpmdir ${TARGETDIR}" --define "_rpmdir ${TARGETDIR}" --define "_buildrootdir ${PWD}/.build" -ba softu2f-system-daemon.spec

selinux-policy:
	@$(MAKE) -C $@

install: ../target/release/softu2f-system-daemon
	install -m 755 ../target/release/softu2f-system-daemon /usr/libexec/softu2f/system-daemon
	install -m 644 softu2f.service /etc/systemd/system/softu2f.service
	install -m 644 softu2f.socket /etc/systemd/system/softu2f.socket
	install -m 644 softu2f-tmpfiles.conf /etc/tmpfiles.d/softu2f.conf
	sudo selinux-policy/softu2f-system-daemon.sh
	sudo systemctl enable softu2f.socket
	sudo systemctl start softu2f.socket

.PHONY: install selinux-policy rpm
