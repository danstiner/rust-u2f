# Rust U2F
[![Build Status](https://travis-ci.org/danstiner/rust-u2f.svg?branch=master)](https://travis-ci.org/danstiner/rust-u2f)

Prototype software-only U2F implementation on Linux implemented in [Rust](https://www.rust-lang.org/)

## Usage

After installing, open Google Chrome or Firefox and use your new virtual U2F device on a site supporting it such as: https://demo.yubico.com/webauthn

More information on U2F: https://www.yubico.com/solutions/fido-u2f/

<p align="center">
  <img alt="SoftU2F demo video" src="https://user-images.githubusercontent.com/52513/35321008-a8ec44f6-009a-11e8-8595-1132190f29ed.gif">
</p>

## Installation

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

Note on Ubuntu 16.04 LTS a reboot is required for changes from [dbus-user-session](https://launchpad.net/ubuntu/xenial/+package/dbus-user-session) to take effect.

## Security

Like any U2F authenticator this program protects against phishing and poorly chosen passwords. However it does not provide the same level of protection against malware that a hardware authenticator does. For some people the protection against phishing and convenience may be worth the security trade-off.

If your machine is compromised by malware, the attacker could steal a copy of the secret keys stored by this authenticator. In this situation you should immediately unregister this authenticator anywhere it is registered in addition to changing the passwords of any potentially compromised account. With a hardware authenticator secret keys never leave the device so in the case of malware you can simply unplug from the infected machine and be confident your accounts are safe from further compromise.

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
