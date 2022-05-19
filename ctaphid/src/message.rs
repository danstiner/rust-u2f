use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, time::Duration};
use thiserror::Error;

use crate::{channel::ChannelId, packet::Packet};

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
const COMMAND_WINK_DATA_LEN: usize = 0;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
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
            id if id >= CTAPHID_VENDOR_FIRST && id <= CTAPHID_VENDOR_LAST => {
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

#[derive(Debug)]
pub struct RequestMessage {
    pub channel_id: ChannelId,
    pub request: Request,
}

impl RequestMessage {
    pub fn decode(packets: &[Packet]) -> Result<Self, RequestMessageDecodeError> {
        if packets.is_empty() {
            return Err(RequestMessageDecodeError::Incomplete);
        }

        let mut payload = Vec::new();
        let mut expected_sequence_number = 0;

        let (channel_id, command, payload_len) = match &packets[0] {
            Packet::Initialization {
                channel_id,
                command,
                data,
                payload_len,
            } => {
                payload.extend_from_slice(&data);
                (*channel_id, *command, *payload_len as usize)
            }
            Packet::Continuation { .. } => {
                return Err(RequestMessageDecodeError::InvalidFirstPacket)
            }
        };

        for packet in packets[1..].iter() {
            match packet {
                Packet::Initialization { .. } => {
                    return Err(RequestMessageDecodeError::InvalidPacketOrder);
                }
                Packet::Continuation {
                    channel_id,
                    data,
                    sequence_number,
                } => {
                    assert_eq!(*channel_id, packets[0].channel_id());
                    assert_eq!(*sequence_number, expected_sequence_number);
                    expected_sequence_number += 1;

                    payload.extend_from_slice(&data);
                }
            }
        }

        let request = Request::decode(command, &payload[0..payload_len])?;

        Ok(Self {
            channel_id,
            request,
        })
    }
}

#[derive(Debug)]
pub enum Request {
    Ping { data: Vec<u8> },
    Msg { data: Vec<u8> },
    Init { nonce: [u8; 8] },
    Cbor { data: Vec<u8> },
    Cancel,
    // Lock time in seconds 0..10. A value of 0 immediately releases the lock
    Lock { lock_time: Duration },
    Wink,
}

impl Request {
    pub fn decode(command: CommandType, data: &[u8]) -> Result<Request, RequestDecodeError> {
        match command {
            CommandType::Msg => Ok(Request::Msg {
                data: data.to_vec(),
            }),
            CommandType::Ping => Ok(Request::Ping {
                data: data.to_vec(),
            }),
            CommandType::Init => {
                if data.len() != COMMAND_INIT_DATA_LEN {
                    Err(RequestDecodeError::PayloadLength {
                        expected_len: COMMAND_INIT_DATA_LEN,
                        actual_len: data.len(),
                    })
                } else {
                    let mut nonce = [0u8; COMMAND_INIT_DATA_LEN];
                    nonce.copy_from_slice(&data[..]);
                    Ok(Request::Init { nonce })
                }
            }
            CommandType::Cbor => Ok(Request::Cbor {
                data: data.to_vec(),
            }),
            CommandType::Cancel => todo!(),
            CommandType::KeepAlive => todo!(),
            CommandType::Wink => Ok(Request::Wink),
            CommandType::Lock => {
                if data.len() != COMMAND_WINK_DATA_LEN {
                    Err(RequestDecodeError::PayloadLength {
                        expected_len: COMMAND_WINK_DATA_LEN,
                        actual_len: data.len(),
                    })
                } else {
                    Ok(Request::Lock {
                        lock_time: Duration::from_secs(data[0].into()),
                    })
                }
            }
            CommandType::Error => Err(RequestDecodeError::UnsupportedCommand(command)),
            CommandType::Vendor { .. } => Err(RequestDecodeError::UnsupportedCommand(command)),
            CommandType::Unknown { .. } => {
                // The Fido v2.0 specification is backwards compatible with U2F
                // authenticators if they responded to unknown messages with
                // the error message InvalidCommand (0x01).
                // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#interoperating-with-ctap1-u2f-authenticators
                Err(RequestDecodeError::UnsupportedCommand(command))
            }
        }
    }
}

#[derive(Debug)]
pub struct ResponseMessage {
    pub channel_id: ChannelId,
    pub response: Response,
}

#[derive(Debug)]
pub enum Response {
    Ping {
        data: Vec<u8>,
    },
    Msg {
        data: Vec<u8>,
    },
    Init {
        nonce: [u8; 8],
        new_channel_id: ChannelId,
        ctaphid_protocol_version: u8,
        major_device_version_number: u8,
        minor_device_version_number: u8,
        build_device_version_number: u8,
        capabilities: CapabilityFlags,
    },
    Cbor {
        data: Vec<u8>,
    },
    KeepAlive {
        status: KeepAliveStatus,
    },
    Error {
        code: ErrorCode,
    },
    Wink,
    Lock,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveStatus {
    Processing = 0x01,
    UserPresenceNeeded = 0x02,
}

impl ResponseMessage {
    pub fn to_packets(&self) -> VecDeque<Packet> {
        let channel_id = self.channel_id;
        match &self.response {
            Response::Ping { data } => Packet::encode_message(channel_id, CommandType::Ping, &data),
            Response::Msg { data } => Packet::encode_message(channel_id, CommandType::Msg, &data),
            Response::Init {
                nonce,
                new_channel_id,
                ctaphid_protocol_version,
                major_device_version_number,
                minor_device_version_number,
                build_device_version_number,
                capabilities,
            } => {
                let mut data = Vec::with_capacity(17);
                data.extend_from_slice(nonce);
                new_channel_id.write(&mut data).unwrap();
                data.push(*ctaphid_protocol_version);
                data.push(*major_device_version_number);
                data.push(*minor_device_version_number);
                data.push(*build_device_version_number);
                data.push(capabilities.bits);
                assert_eq!(data.len(), 17);
                Packet::encode_message(channel_id, CommandType::Init, &data)
            }
            Response::Cbor { data } => Packet::encode_message(channel_id, CommandType::Cbor, &data),
            Response::KeepAlive { status } => {
                Packet::encode_message(channel_id, CommandType::KeepAlive, &[])
            }
            Response::Error { code } => {
                let data = vec![code.to_byte()];
                Packet::encode_message(channel_id, CommandType::Error, &data)
            }
            Response::Wink => Packet::encode_message(channel_id, CommandType::Wink, &[]),
            Response::Lock => Packet::encode_message(channel_id, CommandType::Lock, &[]),
        }
    }
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
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

#[derive(Debug, Error)]
pub enum RequestMessageDecodeError {
    #[error("Incomplete message")]
    Incomplete,

    #[error("InvalidFirstPacket")]
    InvalidFirstPacket,

    #[error("InvalidPacketOrder")]
    InvalidPacketOrder,

    #[error("Request decode error: {0:?}")]
    RequestDecodeError(#[from] RequestDecodeError),
}

#[derive(Debug, Error)]
pub enum RequestDecodeError {
    #[error("Payload length ({actual_len}) longer than expected ({expected_len})")]
    PayloadLength {
        expected_len: usize,
        actual_len: usize,
    },

    #[error("Unsupported command: {0:?}")]
    UnsupportedCommand(CommandType),
}

bitflags! {
    pub struct CapabilityFlags: u8 {
        const WINK = 0b0000_0001; // If set, authenticator implements CTAPHID_WINK function
        const CBOR = 0b0000_0100; // If set, authenticator implements CTAPHID_CBOR function
        const NMSG = 0b0000_1000; // If set, authenticator DOES NOT implement CTAPHID_MSG function
    }
}
