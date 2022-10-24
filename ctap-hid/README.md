# ctap-hid

The Client to Authenticator (CTAP) Protocol allows the [Authenticator API](../fido2-authenticator-api/) to be accessed over a USB transport using the HID (Human Interface Device) protocol. The highest level of the protocol is a transaction, a pair of request and response messages. Messages are in turn fragmented into individual packets which can be encoded as HID reports and sent over the USB transport.

This protocol is defined by the [FIDO2 Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb)
