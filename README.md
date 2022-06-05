# Rust U2F

A software-only [Universal 2nd Factor](https://www.yubico.com/solutions/fido-u2f/) token. Supports Google Chrome and Firefox on Linux. Written in [Rust](https://www.rust-lang.org/).

<p align="center">
  <img src="https://user-images.githubusercontent.com/52513/53316061-32725f80-387b-11e9-8476-36207606db58.png" />
</p>

This program is basically complete, I am not currently planning to add new features like passwordless login the newer [FIDO2 standard](https://fidoalliance.org/specifications/) supports.

## Security

Disclaimer: This is a personal project, I am not a security expert and make no guarantee of security.

A hardware authenticator from [SoloKeys](https://solokeys.com/) or [yubico](https://www.yubico.com/) provides a 2nd-factor for authentication that is both phishing resistant and difficult to clone. They have been audited by independent experts and I used them instead of this software for more sensitive accounts.

This software-only authenticator is phishing resistant, but because it stores [secret keys](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html#site-specific-public-private-key-pairs) and [usage counters](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html#counters-as-a-signal-for-detecting-cloned-u2f-devices) in your [keychain](https://askubuntu.com/questions/1700/what-is-the-keyring-or-keychain) it is *not* clone resistant. If your machine is compromised by malware, the attacker could steal this data and use it together with your account passwords to sign in any time they desire.

## Installation

After installing, test your new virtual FIDO2 device on a site supporting it such as: https://demo.yubico.com/webauthn-technical/registration

### Arch

Install the AUR package maintained by [@grawity](https://github.com/grawity): https://aur.archlinux.org/packages/softu2f/

Then enable and start the installed services:
```bash
systemctl --system enable --now softu2f.socket
systemctl --user   enable --now softu2f.service
```

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

## Architecture

### Background

- [FIDO Specifications](https://fidoalliance.org/specifications/)
- [UHID - User-space I/O driver support for HID subsystem](https://www.kernel.org/doc/Documentation/hid/uhid.txt)
- [HID I/O Transport Drivers in the Linux kernel](https://www.kernel.org/doc/html/latest/hid/hid-transport.html)
- [Chromium's Input Stack](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/input_stack.md)

### FIDO

Conceptually FIDO consists of three pieces:

- A *remote server* that wants to verify a user's identity
- A *user device* that runs a web browser or other client application
- An *authenticator device* that can store keys and attest the user's identify

This project creates a virtual authenticator device that, to web browsers and other client applications, appears nearly identical to a hardware authenticator. Specifically, a hardware authenticator presents itself as a Human Interface Device over a USB transport (USB-HID), while this software creates a virtual HID driven by a service process.

On Linux this is done using [UHID](https://www.kernel.org/doc/Documentation/hid/uhid.txt), a kernel module that allows creating HID devices and controlling them from userspace. One limitation is that our virtual HID devices may not having certain metadata, such as a bus id which is inherit to the USB transport.

This project is split into two programs that coordinate to implement such a virtual HID authenticator.

### system-daemon

This program listens on a socket file for connections from *user-daemon* instances and for each connection uses the `/dev/uhid` character misc-device provided by the `UHID` kernel module to create a HID device with a report descriptor defining it as a FIDO Alliance authenticator device. It then forwards HID report data between the device and *user-daemon* connection. It is essentially a simple broker to allow the *user-daemon* proccess to create authenticator devices. It is usually run by systemd in a privileged context in order to access `/dev/uhid`, but can also be run manually if desired.

It is broken down into the following crates:
- [system-daemon](linux/system-daemon) is the binary itself
- [uhid-tokio](linux/uhid-tokio) provides a [tokio](https://tokio.rs/)-based async interface to the [Linux UHID driver](https://www.kernel.org/doc/Documentation/hid/uhid.txt). It is published to [crates.io](https://crates.io/crates/tokio-linux-uhid) for use independent from this project
- [uhid-sys](linux/uhid-sys) provides FFI bindings to `<linux/uhid.h>` used by *uhid-tokio*. It is also published to [crates.io](https://crates.io/crates/uhid-sys)
- [ctaphid](ctaphid) provides the HID report descriptor that says the virtual HID is an authenticator

### user-daemon

This program runs in the user's session. It connects to the system-daemon's socket file and then reads incoming HID report data, decoding it into the commands as defined by FIDO Client to Authenticator Protocol (CTAP). It responds to those commands, handling all signing and secrets. It verifies user presence by using `libnotify` to show notifications with the option to approve or deny requests to register or authenticate a user.

It is broken down into the following crates:
- [user-daemon](linux/user-daemon) is the binary itself
- [ctaphid](ctaphid) implements the client to authenticator protocol as defined by the FIDO2 specification. As USB authenticators can only receive data as fixed-size HID reports, this protocol lets clients send large messages by packetizing them into a series of HID reports. It also handles potentially concurrent access from multiple clients. So to emulate a USB/HID authenticator, this crate handles decoding the reports back to larger messages, which are themselves encoded authentication requests/responses using either CBOR or a legacy U2F encoding
- [fido2-authenticator-api](fido2-authenticator-api) defines the API for authentication requests and responses, following the FIDO2 specification. *ctaphid* depends on this API and *fido2-authenticator-service* implements this API. It also handles serialization of CBOR messages and the legacy U2F message encoding
- [fido2-authenticator-service](fido2-authenticator-service) implements the actual authentication operations. It does not directly implement secret storage or user presence verification, specific implementations of these are injected as dependencies when the `user-daemon` intializes an authenticator instance

### Diagram

```
+-----------+    +---------+  +-----------------+
| Webserver |    | Keyring |  | Notification UI |
+-----------+    +---------+  +-----------------+
      |               |________________|
      |                      |
      | HTTP(S)              | D-Bus
      |                      |
+-----------+         +---------------+
|  Browser  |         |  user-daemon  |
+-----------+         +---------------+
      |                      |
      | /dev/input/event*    | /run/softu2f/softu2f.sock
      |                      |
      |                      |      User session
------|----------------------|------------------
      |                      |            System
      |                      |       
      |               +---------------+
      |               | system-daemon |
      |               +---------------+
      |                      |
      |                      | /dev/uhid
      |                      |
------|----------------------|------------------
      |                      |            Kernel
+-----------+            +--------+
| evdev     |            |  UHID  |
+-----------+            +--------+
      |                      |
+-----------------------------------------+
|          Kernel HID subsystem           |
+-----------------------------------------+
```

## Building

See `Dockerfile.debian` or `Dockerfile.fedora` for pre-requisite packages that must be installed.

Then run `cd linux && make`.

To install run `cd linux && make install`. The install target uses sudo so you will be prompted for your password.

## Testing

- `cargo test`
- Install locally, then run `cargo run --bin test-authenticator` go through the registration and approval flow.
- Install locally, then run https://github.com/solokeys/fido2-tests

### Bump version

* Run `bumpversion --no-tag patch`
* Update `linux/meta-package/debian/changelog` and amend the commit
* Push and manually tag the release
* Package for all platforms and upload package files

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
