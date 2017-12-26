../target/release/softu2f-systemd-daemon:
	cargo test
	cargo build --release

install: ../target/release/softu2f-systemd-daemon
	install -m 755 ../target/release/softu2f-systemd-daemon /usr/libexec/softu2f-systemd-daemon
	install -m 644 softu2f.service /etc/systemd/system/softu2f.service
	install -m 644 softu2f.socket /etc/systemd/system/softu2f.socket
	install -m 644 tmpfiles/softu2f.conf /etc/tmpfiles.d/softu2f.conf
	sudo ./softu2f_systemd_daemon.sh
	sudo systemctl enable softu2f.socket
	sudo systemctl start softu2f.socket

.PHONY: install
