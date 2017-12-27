export PWD := $(shell pwd)

../target/release/softu2f-systemd-daemon:
	cargo test
	cargo build --release

selinux-policy: selinux-policy/*
	$(MAKE) -C selinux-policy

rpm: softu2f-systemd-daemon.spec
	rpmbuild --define "_sourcedir ${PWD}" --define "_specdir ${PWD}" --define "_builddir ${PWD}" --define "_srcrpmdir ${PWD}" --define "_rpmdir ${PWD}" --define "_buildrootdir ${PWD}/.build" -ba softu2f-systemd-daemon.spec

install: ../target/release/softu2f-systemd-daemon
	install -m 755 ../target/release/softu2f-systemd-daemon /usr/libexec/softu2f-systemd-daemon
	install -m 644 softu2f.service /etc/systemd/system/softu2f.service
	install -m 644 softu2f.socket /etc/systemd/system/softu2f.socket
	install -m 644 softu2f-tmpfiles.conf /etc/tmpfiles.d/softu2f.conf
	sudo selinux-policy/softu2f_systemd_daemon.sh
	sudo systemctl enable softu2f.socket
	sudo systemctl start softu2f.socket

.PHONY: install selinux-policy rpm
