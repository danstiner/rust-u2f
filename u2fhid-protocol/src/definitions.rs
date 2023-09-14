use bitflags::bitflags;
use std::cmp;
use std::collections::vec_deque::VecDeque;
use std::io::{Cursor, Read};
use std::time::Duration;
use thiserror::Error;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde_derive::{Deserialize, Serialize};

pub const U2FHID_PROTOCOL_VERSION: u8 = 2;

const HID_REPORT_LEN: usize = 64;
const INITIAL_PACKET_DATA_LEN: usize = HID_REPORT_LEN - 7;
const CONTINUATION_PACKET_DATA_LEN: usize = HID_REPORT_LEN - 5;

const FRAME_TYPE_INIT: u8 = 0b1000_0000;
const FRAME_TYPE_CONT: u8 = 0b0000_0000;
const FRAME_TYPE_MASK: u8 = FRAME_TYPE_INIT;

const U2FHID_PING: u8 = FRAME_TYPE_INIT | 0x01; // Echo data through local processor only
const U2FHID_MSG: u8 = FRAME_TYPE_INIT | 0x03; // Send U2F message frame
const U2FHID_LOCK: u8 = FRAME_TYPE_INIT | 0x04; // Send lock channel command
const U2FHID_INIT: u8 = FRAME_TYPE_INIT | 0x06; // Channel initialization
const U2FHID_WINK: u8 = FRAME_TYPE_INIT | 0x08; // Send device identification wink
const U2FHID_SYNC: u8 = FRAME_TYPE_INIT | 0x3c; // Protocol resync command
const U2FHID_ERROR: u8 = FRAME_TYPE_INIT | 0x3f; // Error response

const U2FHID_VENDOR_FIRST: u8 = FRAME_TYPE_INIT | 0x40; // First vendor defined command
const U2FHID_VENDOR_LAST: u8 = FRAME_TYPE_INIT | 0x7f; // Last vendor defined command

const COMMAND_INIT_DATA_LEN: usize = 8;
const COMMAND_WINK_DATA_LEN: usize = 1;

pub const BROADCAST_CHANNEL_ID: ChannelId = ChannelId(0xffff_ffff);

pub fn packet_timeout_duration() -> Duration {
    Duration::from_millis(500)
}
pub fn transaction_timeout_duration() -> Duration {
    Duration::from_millis(3000)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ChannelId(pub u32);

impl ChannelId {
    pub fn checked_add(self, number: u32) -> Option<ChannelId> {
        self.0.checked_add(number).map(ChannelId)
    }

    pub fn write<W: WriteBytesExt>(&self, write: &mut W) {
        write.write_u32::<BigEndian>(self.0).unwrap();
    }
}

bitflags! {
    pub struct CapabilityFlags: u8 {
        const CAPFLAG_WINK = 0b0000_0001;
    }
}

#[derive(Debug)]
pub enum ErrorCode {
    None,
    InvalidChannel,
    InvalidCommand,
    InvalidParameter,
    InvalidMessageLength,
    InvalidMessageSequencing,
    MessageTimedOut,
    ChannelBusy,
    CommandRequiresChannelLock,
    SyncCommandFailed,
    Other,
}

impl ErrorCode {
    fn to_byte(&self) -> u8 {
        match self {
            ErrorCode::None => 0x00,
            ErrorCode::InvalidCommand => 0x01,
            ErrorCode::InvalidParameter => 0x02,
            ErrorCode::InvalidMessageLength => 0x03,
            ErrorCode::InvalidMessageSequencing => 0x04,
            ErrorCode::MessageTimedOut => 0x05,
            ErrorCode::ChannelBusy => 0x06,
            ErrorCode::CommandRequiresChannelLock => 0x0a,
            ErrorCode::SyncCommandFailed => 0x0b,
            ErrorCode::InvalidChannel => 0x0b,
            ErrorCode::Other => 0x7f,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
pub enum Command {
    Msg,
    Ping,
    Init,
    Error,
    Wink,
    Lock,
    Sync,
    Vendor { identifier: u8 },
    Unknown { identifier: u8 },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Packet {
    Initialization {
        channel_id: ChannelId,
        command: Command,
        data: Vec<u8>,
        payload_len: u16,
    },
    Continuation {
        channel_id: ChannelId,
        sequence_number: u8,
        data: Vec<u8>,
    },
}

impl Packet {
    pub fn channel_id(&self) -> ChannelId {
        match *self {
            Packet::Initialization { channel_id, .. } => channel_id,
            Packet::Continuation { channel_id, .. } => channel_id,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Packet, ()> {
        assert_eq!(bytes.len(), HID_REPORT_LEN + 1);
        let mut reader = Cursor::new(bytes);
        reader.read_u8().unwrap(); // TODO why do we have this extra byte to skip here
        let channel_id = ChannelId(reader.read_u32::<BigEndian>().unwrap());
        let first_byte = reader.read_u8().unwrap();
        if first_byte & FRAME_TYPE_MASK == FRAME_TYPE_INIT {
            let command = match first_byte {
                U2FHID_MSG => Command::Msg,
                U2FHID_PING => Command::Ping,
                U2FHID_INIT => Command::Init,
                U2FHID_ERROR => Command::Error,
                U2FHID_WINK => Command::Wink,
                U2FHID_LOCK => Command::Lock,
                U2FHID_SYNC => Command::Sync,
                id if id >= U2FHID_VENDOR_FIRST && id <= U2FHID_VENDOR_LAST => {
                    Command::Vendor { identifier: id }
                }
                id => Command::Unknown { identifier: id },
            };
            let payload_len = reader.read_u16::<BigEndian>().unwrap();
            let mut packet_data = vec![0u8; INITIAL_PACKET_DATA_LEN];
            reader.read_exact(&mut packet_data[..]).unwrap();
            Ok(Packet::Initialization {
                channel_id,
                command,
                data: packet_data,
                payload_len,
            })
        } else {
            let sequence_number = first_byte;
            let mut packet_data = vec![0u8; CONTINUATION_PACKET_DATA_LEN];
            reader.read_exact(&mut packet_data[..]).unwrap();
            Ok(Packet::Continuation {
                channel_id,
                sequence_number,
                data: packet_data,
            })
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HID_REPORT_LEN);
        match self {
            Packet::Initialization {
                channel_id,
                command,
                data,
                payload_len,
            } => {
                // Offset Length Mnemonic Description
                // 0      4      CID      Channel identifier
                channel_id.write(&mut bytes);

                // 4      1      CMD      Command identifier (bit 7 always set)
                let command_byte = match command {
                    Command::Msg => U2FHID_MSG,
                    Command::Ping => U2FHID_PING,
                    Command::Init => U2FHID_INIT,
                    Command::Error => U2FHID_ERROR,
                    Command::Wink => U2FHID_WINK,
                    Command::Lock => U2FHID_LOCK,
                    Command::Sync => U2FHID_SYNC,
                    Command::Vendor { identifier } => *identifier,
                    Command::Unknown { identifier } => *identifier,
                };
                bytes.push(command_byte);

                // 5      1      BCNTH    High part of payload length
                // 6      1      BCNTL    Low part of payload length
                bytes.write_u16::<BigEndian>(*payload_len).unwrap();

                // 7      (s-7)  DATA     Payload data (s is equal to the fixed packet size)
                bytes.extend_from_slice(data);
            }
            Packet::Continuation {
                channel_id,
                sequence_number,
                data,
            } => {
                // Offset Length Mnemonic Description
                // 0      4      CID      Channel identifier
                channel_id.write(&mut bytes);

                // 4      1      SEQ      Packet sequence 0x00..0x7f (bit 7 always cleared)
                assert_eq!(sequence_number & FRAME_TYPE_MASK, FRAME_TYPE_CONT);
                bytes.push(*sequence_number);

                // 5      (s-5)  DATA     Payload data (s is equal to the fixed packet size)
                bytes.extend_from_slice(data);
            }
        }

        // Zero-fill remainder of packet
        bytes.resize(HID_REPORT_LEN, 0u8);

        bytes
    }
}

#[derive(Debug)]
pub struct Request {
    pub channel_id: ChannelId,
    pub message: RequestMessage,
}

#[derive(Debug)]
pub enum RequestMessage {
    EncapsulatedRequest { data: Vec<u8> },
    Init { nonce: [u8; 8] },
    // Lock time in seconds 0..10. A value of 0 immediately releases the lock
    Lock { lock_time: Duration },
    Ping { data: Vec<u8> },
    Wink,
}

impl RequestMessage {
    pub fn decode(
        command: &Command,
        data: &[u8],
    ) -> Result<RequestMessage, RequestMessageDecodeError> {
        match *command {
            Command::Msg => Ok(RequestMessage::EncapsulatedRequest {
                data: data.to_vec(),
            }),
            Command::Ping => Ok(RequestMessage::Ping {
                data: data.to_vec(),
            }),
            Command::Init => {
                if data.len() != COMMAND_INIT_DATA_LEN {
                    Err(RequestMessageDecodeError::PayloadLength {
                        expected_len: COMMAND_INIT_DATA_LEN,
                        actual_len: data.len(),
                    })
                } else {
                    let mut nonce = [0u8; COMMAND_INIT_DATA_LEN];
                    nonce.copy_from_slice(data);
                    Ok(RequestMessage::Init { nonce })
                }
            }
            Command::Wink => Ok(RequestMessage::Wink),
            Command::Lock => {
                if data.len() != COMMAND_WINK_DATA_LEN {
                    Err(RequestMessageDecodeError::PayloadLength {
                        expected_len: COMMAND_WINK_DATA_LEN,
                        actual_len: data.len(),
                    })
                } else {
                    Ok(RequestMessage::Lock {
                        lock_time: Duration::from_secs(data[0].into()),
                    })
                }
            }
            Command::Sync => Err(RequestMessageDecodeError::UnsupportedCommand(*command)),
            Command::Error => Err(RequestMessageDecodeError::UnsupportedCommand(*command)),
            Command::Vendor { .. } => Err(RequestMessageDecodeError::UnsupportedCommand(*command)),

            Command::Unknown { .. } => {
                // The Fido v2.0 specification is backwards compatible with U2F
                // authenticators if they responded to unknown messages with
                // the error message InvalidCommand (0x01).
                // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#interoperating-with-ctap1-u2f-authenticators
                Err(RequestMessageDecodeError::UnsupportedCommand(*command))
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum RequestMessageDecodeError {
    #[error("Payload length ({actual_len}) longer than expected ({expected_len})")]
    PayloadLength {
        expected_len: usize,
        actual_len: usize,
    },

    #[error("Unsupported command: {0:?}")]
    UnsupportedCommand(Command),
}

#[derive(Debug)]
pub struct Response {
    pub channel_id: ChannelId,
    pub message: ResponseMessage,
}

impl Response {
    pub fn to_packets(&self) -> VecDeque<Packet> {
        let channel_id = self.channel_id;
        match &self.message {
            ResponseMessage::EncapsulatedResponse { data } => {
                encode_response(channel_id, Command::Msg, data)
            }
            ResponseMessage::Init {
                nonce,
                new_channel_id,
                u2fhid_protocol_version,
                major_device_version_number,
                minor_device_version_number,
                build_device_version_number,
                capabilities,
            } => {
                let mut data = Vec::with_capacity(17);
                data.extend_from_slice(nonce);
                new_channel_id.write(&mut data);
                data.push(*u2fhid_protocol_version);
                data.push(*major_device_version_number);
                data.push(*minor_device_version_number);
                data.push(*build_device_version_number);
                data.push(capabilities.bits);
                assert_eq!(data.len(), 17);
                encode_response(channel_id, Command::Init, &data)
            }
            ResponseMessage::Pong { data } => encode_response(channel_id, Command::Ping, data),
            ResponseMessage::Error { code } => {
                let data = vec![code.to_byte()];
                encode_response(channel_id, Command::Error, &data)
            }
            ResponseMessage::Wink => encode_response(channel_id, Command::Wink, &[]),
            ResponseMessage::Lock => encode_response(channel_id, Command::Lock, &[]),
        }
    }
}

#[derive(Debug)]
pub enum ResponseMessage {
    EncapsulatedResponse {
        data: Vec<u8>,
    },
    Init {
        nonce: [u8; 8],
        new_channel_id: ChannelId,
        u2fhid_protocol_version: u8,
        major_device_version_number: u8,
        minor_device_version_number: u8,
        build_device_version_number: u8,
        capabilities: CapabilityFlags,
    },
    Pong {
        data: Vec<u8>,
    },
    Error {
        code: ErrorCode,
    },
    Wink,
    Lock,
}

impl From<u2f_core::Response> for ResponseMessage {
    fn from(response: u2f_core::Response) -> ResponseMessage {
        ResponseMessage::EncapsulatedResponse {
            data: response.into_bytes(),
        }
    }
}

fn encode_response(channel_id: ChannelId, command: Command, data: &[u8]) -> VecDeque<Packet> {
    let mut packets = VecDeque::new();
    let payload_len = data.len() as u16;
    let split_index = cmp::min(data.len(), INITIAL_PACKET_DATA_LEN);
    let (initial, remaining) = data.split_at(split_index);
    packets.push_back(Packet::Initialization {
        channel_id,
        command,
        payload_len,
        data: initial.to_vec(),
    });
    for (i, chunk) in remaining.chunks(CONTINUATION_PACKET_DATA_LEN).enumerate() {
        packets.push_back(Packet::Continuation {
            channel_id,
            sequence_number: i as u8,
            data: chunk.to_vec(),
        });
    }
    packets
}
