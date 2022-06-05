mod api;
mod channel;
mod message;
mod packet;
mod protocol;
mod server;

use lazy_static::lazy_static;
use std::time::Duration;

pub use api::Adapter;
pub use packet::Packet;
pub use server::Server;

pub const CTAPHID_PROTOCOL_VERSION: u8 = 2;

/// HID Report Descriptor to be used for this implementation of the CTAP HID protocol.
///
/// See:
/// - http://www.usb.org/developers/hidpage/HUTRR48.pdf
/// - https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-discovery
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

/// The single type of input reports for [REPORT_DESCRIPTOR](REPORT_DESCRIPTOR)
pub const REPORT_TYPE_INPUT: u8 = 0;

/// The single type of output reports for [REPORT_DESCRIPTOR](REPORT_DESCRIPTOR)
pub const REPORT_TYPE_OUTPUT: u8 = 0;

lazy_static! {
    /// A CTAPHID_KEEPALIVE command SHOULD be sent at least every 100ms and whenever the status changes
    /// while processing a CTAPHID_MSG. A KEEPALIVE sent by an authenticator does not constitute a
    /// response and does therefore not end an ongoing transaction.
    ///
    /// We choose to send at twice that rate as for a safety margin.
    pub static ref KEEPALIVE_INTERVAL: Duration = Duration::from_millis(50);

    pub static ref PACKET_TIMEOUT: Duration = Duration::from_millis(500);

    pub static ref TRANSACTION_TIMEOUT: Duration = Duration::from_millis(3000);
}

#[cfg(test)]
mod tests {
    use super::*;

    // In REPORT_DESCRIPTOR, input and output reports have 64 bytes of data.
    // This must match [`HID_REPORT_LEN`](packets::HID_REPORT_LEN)
    // TODO assert this by parsing the report descriptor and maybe make it configurable.
    #[test]
    fn test_report_descriptor_report_lengths() {
        // Input report data is count=64 values of size=8 bits.
        assert_eq!(REPORT_DESCRIPTOR[15], 8);
        assert_eq!(REPORT_DESCRIPTOR[17] as usize, packet::HID_REPORT_LEN);

        // Output report data is count=64 values of size=8 bits.
        assert_eq!(REPORT_DESCRIPTOR[28], 8);
        assert_eq!(REPORT_DESCRIPTOR[30] as usize, packet::HID_REPORT_LEN);
    }
}
