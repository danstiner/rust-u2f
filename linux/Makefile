pwd := $(shell pwd)
targetdir := ${pwd}/target/fedora
selinuxpolicydir := ${pwd}/system-daemon/selinux-policy
systemdaemondir := ${pwd}/system-daemon
userdaemondir := ${pwd}/user-daemon

default: build

build:
	cargo build

install: build
	sudo mkdir -p /usr/lib/softu2f
	sudo install -m 755 target/debug/softu2f-system-daemon /usr/lib/softu2f/system-daemon
	sudo install -m 644 ${systemdaemondir}/softu2f.service /etc/systemd/system/softu2f.service
	sudo install -m 644 ${systemdaemondir}/softu2f.socket /etc/systemd/system/softu2f.socket
	sudo install -m 644 ${systemdaemondir}/softu2f-tmpfiles.conf /etc/tmpfiles.d/softu2f.conf
	if [ -n "$$(which sestatus 1>/dev/null 2>&1)" ]; then \
		sudo ${selinuxpolicydir}/softu2f-system-daemon.sh; \
	fi
	sudo install -m 755 target/debug/softu2f-user-daemon /usr/lib/softu2f/user-daemon
	sudo install -m 644 ${userdaemondir}/softu2f.service /etc/systemd/user/softu2f.service
	sudo systemctl daemon-reload
	systemctl --user daemon-reload

	# Stop existing services if this is a re-install
	systemctl --user stop softu2f.service
	sudo systemctl --system stop softu2f.service

	# Enable and start services (system service is started via the socket service)
	sudo systemctl --system enable softu2f.socket
	sudo systemctl --system start softu2f.socket
	systemctl --user enable softu2f.service
	systemctl --user restart softu2f.service

uninstall:
	-systemctl --user disable softu2f.service
	-systemctl --user stop softu2f.service
	-sudo systemctl --system disable softu2f.socket
	-sudo systemctl --system stop softu2f.service
	-sudo rm /usr/lib/softu2f/system-daemon
	-sudo rm /etc/systemd/system/softu2f.service
	-sudo rm /etc/systemd/system/softu2f.socket
	-sudo rm /etc/tmpfiles.d/softu2f.conf
	-sudo rm /usr/lib/softu2f/user-daemon
	-sudo rm /etc/systemd/user/softu2f.service
	-sudo semodule -r softu2f-system-daemon

rpm: softu2f.spec rpm-selinux-policy rpm-system-daemon rpm-user-daemon
	rpmbuild --define "_sourcedir ${pwd}" --define "_specdir ${pwd}" --define "_builddir ${pwd}" --define "_srcrpmdir ${targetdir}" --define "_rpmdir ${targetdir}" --define "_buildrootdir ${pwd}/.build" -ba softu2f.spec

rpm-selinux-policy:
	cd "${selinuxpolicydir}" && make -f /usr/share/selinux/devel/Makefile
	rpmbuild --define "_sourcedir ${selinuxpolicydir}" --define "_specdir ${selinuxpolicydir}" --define "_builddir ${selinuxpolicydir}" --define "_srcrpmdir ${targetdir}" --define "_rpmdir ${targetdir}" --define "_buildrootdir ${pwd}/.build" -ba "${selinuxpolicydir}/softu2f-system-daemon-selinux.spec"
	cd "${selinuxpolicydir}" && make -f /usr/share/selinux/devel/Makefile clean

rpm-system-daemon: rpm-selinux-policy rpm-user-daemon
	rpmbuild --define "_sourcedir ${systemdaemondir}" --define "_specdir ${systemdaemondir}" --define "_builddir ${systemdaemondir}" --define "_srcrpmdir ${targetdir}" --define "_rpmdir ${targetdir}" --define "_buildrootdir ${pwd}/.build" -ba "${systemdaemondir}/softu2f-system-daemon.spec"

rpm-user-daemon:
	rpmbuild --define "_sourcedir ${userdaemondir}" --define "_specdir ${userdaemondir}" --define "_builddir ${userdaemondir}" --define "_srcrpmdir ${targetdir}" --define "_rpmdir ${targetdir}" --define "_buildrootdir ${pwd}/.build" -ba "${userdaemondir}/softu2f-user-daemon.spec"

.PHONY: build
.PHONY: install uninstall
.PHONY: rpm make-selinux-policy rpm-selinux-policy rpm-system-daemon rpm-user-daemon
