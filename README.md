# Rust U2F
[![Build Status](https://travis-ci.org/danstiner/rust-u2f.svg?branch=master)](https://travis-ci.org/danstiner/rust-u2f)

A software-only [Universal 2nd Factor](https://www.yubico.com/solutions/fido-u2f/) token. Supports Google Chrome and Firefox on Linux. Written in [Rust](https://www.rust-lang.org/).

<p align="center">
  <img src="https://user-images.githubusercontent.com/52513/53316061-32725f80-387b-11e9-8476-36207606db58.png" />
</p>

This program is basically complete, I am not currently planning to add new features like passwordless login the newer [FIDO2 standard](https://fidoalliance.org/specifications/) supports.

## Security

Disclaimer: This is a personal project, I am not a security expert and make no guarantee of security.

Like any U2F authenticator this program provides a degree of protection against phishing and poorly chosen passwords. It does **not** provide the same level of protection against malware that a hardware authenticator does. For some people the protection against phishing and convenience may be worth the security trade-off.

If your machine is compromised by malware, the attacker could steal a copy of the secret keys stored by this authenticator. In this situation you should immediately unregister this authenticator anywhere it is registered in addition to changing the passwords of any potentially compromised accounts. With a hardware authenticator secret keys never leave the device, so in the case of malware you can simply unplug from the infected machine and be confident your accounts are safe from further compromise.

## Installation

### Arch

See https://aur.archlinux.org/packages/softu2f/

### Fedora

```bash
curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.rpm.sh | sudo bash
sudo dnf install softu2f
systemctl --user start softu2f
```

### Ubuntu

```bash
sudo apt install -y curl
curl -s https://packagecloud.io/install/repositories/danstiner/softu2f/script.deb.sh | sudo bash
sudo apt install -y softu2f
systemctl --user start softu2f
```

After installing, use your new virtual U2F device on a site supporting it such as: https://demo.yubico.com/webauthn-technical/registration

Note on Ubuntu 16.04 LTS a reboot is required for changes from [dbus-user-session](https://launchpad.net/ubuntu/xenial/+package/dbus-user-session) to take effect.

## Building

See `Dockerfile.debian` or `Dockerfile.fedora` for pre-requisite packages that must be installed.

Then run `cd linux && make`.

To install run `cd linux && make install`. The install target uses sudo so you will be prompted for your password.

## Developing

### Version Bump

Start with a clean working directory on the master branch.

```
pip3 install --upgrade bumpversion
bumpversion patch
```

Amend the commit created by bumpversion with an updated [debian package changelog file](linux/meta-package/debian/changelog). Then validate packages can be generated for each platform by running `./package.sh`. Finally, push to master.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
