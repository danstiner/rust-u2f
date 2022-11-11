mod api;
mod channel;
mod packet;
mod protocol;
mod request;
mod response;
mod server;
pub mod u2f;

use bitflags::bitflags;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub use api::SimpleAdapter;
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

const COMMAND_TYPE_MASK: u8 = 0b0111_1111;

// Command identifiers
const CTAPHID_PING: u8 = 0x01;
const CTAPHID_MSG: u8 = 0x03;
const CTAPHID_LOCK: u8 = 0x04;
const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_WINK: u8 = 0x08;
const CTAPHID_CBOR: u8 = 0x10;
const CTAPHID_CANCEL: u8 = 0x11;
const CTAPHID_ERROR: u8 = 0x3f;
const CTAPHID_KEEPALIVE: u8 = 0x3b;

const CTAPHID_VENDOR_FIRST: u8 = 0x40; // First vendor defined command
const CTAPHID_VENDOR_LAST: u8 = 0x7f; // Last vendor defined command

const COMMAND_INIT_DATA_LEN: usize = 8;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum CommandType {
    Ping,      // Mandatory: echo data for debugging and performance testing
    Msg,       // Mandatory: encapsulated CTAP1/U2F message
    Init,      // Mandatory: Channel initialization and synchronization
    Cbor,      // Mandatory: Encapsulated CTAP CBOR message
    Cancel,    // Mandatory: Cancel any outstand requests on the channel
    KeepAlive, // Mandatory: Sent while processing a CTAPHID_MSG
    Error,     // Mandatory: Error response
    Lock,      // Optional: Lock channel
    Wink,      // Optional: Device identification wink
    Vendor { identifier: u8 },
    Unknown { identifier: u8 },
}

impl CommandType {
    pub fn from_byte(byte: u8) -> CommandType {
        match byte & COMMAND_TYPE_MASK {
            CTAPHID_PING => CommandType::Ping,
            CTAPHID_MSG => CommandType::Msg,
            CTAPHID_INIT => CommandType::Init,
            CTAPHID_CBOR => CommandType::Cbor,
            CTAPHID_CANCEL => CommandType::Cancel,
            CTAPHID_KEEPALIVE => CommandType::KeepAlive,
            CTAPHID_LOCK => CommandType::Lock,
            CTAPHID_WINK => CommandType::Wink,
            id if (CTAPHID_VENDOR_FIRST..=CTAPHID_VENDOR_LAST).contains(&id) => {
                CommandType::Vendor { identifier: id }
            }
            id => CommandType::Unknown { identifier: id },
        }
    }

    pub fn to_byte(&self) -> u8 {
        match self {
            CommandType::Ping => CTAPHID_PING,
            CommandType::Msg => CTAPHID_MSG,
            CommandType::Init => CTAPHID_INIT,
            CommandType::Cbor => CTAPHID_CBOR,
            CommandType::Cancel => CTAPHID_CANCEL,
            CommandType::KeepAlive => CTAPHID_KEEPALIVE,
            CommandType::Error => CTAPHID_ERROR,
            CommandType::Lock => CTAPHID_LOCK,
            CommandType::Wink => CTAPHID_WINK,
            CommandType::Vendor { identifier } => *identifier,
            CommandType::Unknown { identifier } => *identifier,
        }
    }
}

bitflags! {
    pub struct CapabilityFlags: u8 {
        const WINK = 0b0000_0001; // If set, authenticator implements CTAPHID_WINK function
        const CBOR = 0b0000_0100; // If set, authenticator implements CTAPHID_CBOR function
        const NMSG = 0b0000_1000; // If set, authenticator DOES NOT implement CTAPHID_MSG function
    }
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    None = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidMessageLength = 0x03,
    InvalidMessageSequencing = 0x04,
    MessageTimedOut = 0x05,
    ChannelBusy = 0x06,
    CommandRequiresChannelLock = 0x0a,
    InvalidChannel = 0x0b,
    Other = 0x7f,
}

impl ErrorCode {
    fn to_byte(self) -> u8 {
        self as u8
    }
}

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
