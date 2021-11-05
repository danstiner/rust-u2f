export PWD := $(shell pwd)
export TARGETDIR := ${PWD}/../target/fedora

rpm: selinux-policy
	rpmbuild --define "_sourcedir ${PWD}" --define "_specdir ${PWD}" --define "_builddir ${PWD}" --define "_srcrpmdir ${TARGETDIR}" --define "_rpmdir ${TARGETDIR}" --define "_buildrootdir ${PWD}/.build" -ba softu2f-system-daemon.spec

selinux-policy:
	@$(MAKE) -C $@

install:
	install -m 755 ../target/release/softu2f-system-daemon /usr/lib/softu2f/system-daemon
	install -m 644 softu2f.service /etc/systemd/system/softu2f.service
	install -m 644 softu2f.socket /etc/systemd/system/softu2f.socket
	install -m 644 softu2f-tmpfiles.conf /etc/tmpfiles.d/softu2f.conf
	selinux-policy/softu2f-system-daemon.sh
	systemctl --system enable softu2f.socket
	systemctl --system start softu2f.socket

uninstall:
	systemctl --system disable softu2f.socket
	systemctl --system stop softu2f.service
	rm /usr/lib/softu2f/system-daemon
	rm /etc/systemd/system/softu2f.service
	rm /etc/systemd/system/softu2f.socket
	rm /etc/tmpfiles.d/softu2f.conf
	# TODO uninstall selinux-policy/softu2f-system-daemon

.PHONY: install uninstall selinux-policy rpm
