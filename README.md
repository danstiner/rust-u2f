# Rust U2F
[![Build Status](https://travis-ci.org/danstiner/rust-u2f.svg?branch=master)](https://travis-ci.org/danstiner/rust-u2f)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fdanstiner%2Frust-u2f.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fdanstiner%2Frust-u2f?ref=badge_shield)

In-progress software-only U2F implementation on Linux using Rust

## Usage

After installing, open Google Chrome or Firefox and use your new virtual U2F device on a site supporting it such as: https://demo.yubico.com/u2f

More information on U2F: https://www.yubico.com/solutions/fido-u2f/

<p align="center">
  <img alt="SoftU2F demo video" src="https://user-images.githubusercontent.com/52513/35321008-a8ec44f6-009a-11e8-8595-1132190f29ed.gif">
</p>

### Fedora Installation
```bash
curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.rpm.sh | sudo bash
sudo dnf install softu2f
systemctl --user start softu2f
```

### Ubuntu Installation
```bash
sudo apt install -y curl
curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.deb.sh | sudo bash
sudo apt install -y softu2f
systemctl --user start softu2f
```

Note: on Ubuntu 16.04 LTS a reboot is required for changes from [dbus-user-session](https://launchpad.net/ubuntu/xenial/+package/dbus-user-session) to take effect.

## Building

### Fedora
```bash
dnf install clang dbus-devel openssl-devel protobuf-compiler systemd-devel rpm-build selinux-devel 
```

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.


[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fdanstiner%2Frust-u2f.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fdanstiner%2Frust-u2f?ref=badge_large)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.