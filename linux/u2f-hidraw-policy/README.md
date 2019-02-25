# u2f-hidraw-policy

If you have a U2F token and want your udev-using Linux desktop system to detect it as a security token and allow the logged in user to access it (via Chromium, for example), install this.

Unlike the Yubico sample udev rule, this should work for any compliant U2F device, including non-Yubico devices and as-yet-unreleased devices.
