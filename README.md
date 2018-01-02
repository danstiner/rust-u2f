# SoftU2F for Linux
[![Build Status](https://travis-ci.org/danstiner/softu2f-linux.svg?branch=master)](https://travis-ci.org/danstiner/softu2f-linux)

In-progress software-only U2F implementation on linux using Rust and UHID

# Installation

## Fedora
```bash
$ curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.rpm.sh | sudo bash
$ sudo dnf install softu2f
$ systemctl --user start softu2f
```

## Ubuntu
```bash
$ sudo apt install -y curl
$ curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.deb.sh | sudo bash
$ sudo apt install -y softu2f
$ systemctl --user start softu2f
```

If using Ubuntu 16.04 LTS a reboot is required for changes from [dbus-user-session](https://launchpad.net/ubuntu/xenial/+package/dbus-user-session) to take effect.
