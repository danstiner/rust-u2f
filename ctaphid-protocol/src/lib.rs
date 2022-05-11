extern crate bitflags;
extern crate byteorder;
extern crate futures;
extern crate itertools;
extern crate pin_project;
extern crate serde;
extern crate serde_derive;
extern crate thiserror;
extern crate tokio_tower;
extern crate tracing;
extern crate u2f_core;

#[cfg(test)]
extern crate tokio;

#[cfg(test)]
extern crate tokio_stream;

mod commands;
mod packets;
mod protocol_state_machine;
mod server;

pub use server::Server;

pub const CTAPHID_PROTOCOL_VERSION: u8 = 2;

// HID Report Descriptor from:
// - http://www.usb.org/developers/hidpage/HUTRR48.pdf
// - https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-discovery
pub const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, /* Usage Page: FIDO Alliance Page (0xF1D0)     */
    0x09, 0x01, /*       Usage: CTAPHID Authenticator Device (0x01)  */
    0xa1, 0x01, /*       Collection: Application                     */
    0x09, 0x20, /*       - Usage: Input Report Data (0x20)           */
    0x15, 0x00, /*       - Logical Minimum (0)                       */
    0x26, 0xff, 0x00, /* - Logical Maximum (255)                     */
    0x75, 0x08, /*       - Report Size (8)                           */
    0x95, 0x40, /*       - Report Count (64)                         */
    0x81, 0x02, /*       - Input (Data, Absolute, Variable)          */
    0x09, 0x21, /*       - Usage: Input Report Data (0x21)           */
    0x15, 0x00, /*       - Logical Minimum (0)                       */
    0x26, 0xff, 0x00, /* - Logical Maximum (255)                     */
    0x75, 0x08, /*       - Report Size (8)                           */
    0x95, 0x40, /*       - Report Count (64)                         */
    0x91, 0x02, /*       - Output (Data, Absolute, Variable)         */
    0xc0, /*             End Collection                              */
];
