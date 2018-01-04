# SoftU2F for Linux
[![Build Status](https://travis-ci.org/danstiner/softu2f-linux.svg?branch=master)](https://travis-ci.org/danstiner/softu2f-linux)

In-progress software-only U2F implementation on Linux using Rust

## Usage

After installing, open Google Chrome or Firefox and use your new virtual U2F device on a site supporting it such as: https://demo.yubico.com/u2f

More information on U2F: https://www.yubico.com/solutions/fido-u2f/

### Fedora Installation
```bash
$ curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.rpm.sh | sudo bash
$ sudo dnf install softu2f
$ systemctl --user start softu2f
```

### Ubuntu Installation
```bash
$ sudo apt install -y curl
$ curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.deb.sh | sudo bash
$ sudo apt install -y softu2f
$ systemctl --user start softu2f
```

Note: on Ubuntu 16.04 LTS a reboot is required for changes from [dbus-user-session](https://launchpad.net/ubuntu/xenial/+package/dbus-user-session) to take effect.

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Futures by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
