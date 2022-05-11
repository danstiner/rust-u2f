use bitflags::bitflags;
use std::{collections::VecDeque, time::Duration};
use thiserror::Error;

use crate::packets::{ChannelId, CommandType, Packet};

const COMMAND_INIT_DATA_LEN: usize = 8;
const COMMAND_WINK_DATA_LEN: usize = 0;

#[derive(Debug)]
pub struct RequestMessage {
    pub channel_id: ChannelId,
    pub request: Request,
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
    pub fn decode(command: &CommandType, data: &[u8]) -> Result<Request, RequestDecodeError> {
        match command {
            &CommandType::Msg => Ok(Request::Msg {
                data: data.to_vec(),
            }),
            &CommandType::Ping => Ok(Request::Ping {
                data: data.to_vec(),
            }),
            &CommandType::Init => {
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
            CommandType::Cbor => todo!(),
            CommandType::Cancel => todo!(),
            CommandType::KeepAlive => todo!(),
            &CommandType::Wink => Ok(Request::Wink),
            &CommandType::Lock => {
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
            &CommandType::Error => Err(RequestDecodeError::UnsupportedCommand(*command)),
            &CommandType::Vendor { .. } => Err(RequestDecodeError::UnsupportedCommand(*command)),
            &CommandType::Unknown { .. } => {
                // The Fido v2.0 specification is backwards compatible with U2F
                // authenticators if they responded to unknown messages with
                // the error message InvalidCommand (0x01).
                // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#interoperating-with-ctap1-u2f-authenticators
                Err(RequestDecodeError::UnsupportedCommand(*command))
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
    Pong {
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
            Response::Pong { data } => Packet::encode_message(channel_id, CommandType::Ping, &data),
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

impl From<u2f_core::Response> for Response {
    fn from(response: u2f_core::Response) -> Response {
        Response::Msg {
            data: response.into_bytes(),
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
