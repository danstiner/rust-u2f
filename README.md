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
$ curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.deb.sh | sudo bash
$ sudo apt install softu2f
$ systemctl --user start softu2f
```
