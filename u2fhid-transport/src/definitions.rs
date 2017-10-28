use std::cmp;
use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

pub const MAJOR_DEVICE_VERSION_NUMBER: u8 = 0;
pub const MINOR_DEVICE_VERSION_NUMBER: u8 = 1;
pub const BUILD_DEVICE_VERSION_NUMBER: u8 = 0;

pub const U2FHID_PROTOCOL_VERSION: u8 = 2;

const HID_REPORT_LEN: usize = 64;
const INITIAL_PACKET_DATA_LEN: usize = HID_REPORT_LEN - 7;
const CONTINUATION_PACKET_DATA_LEN: usize = HID_REPORT_LEN - 5;

const FRAME_TYPE_INIT: u8 = 0b10000000;
const FRAME_TYPE_CONT: u8 = 0b00000000;
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

pub type ChannelId = u32;

bitflags! {
    pub struct CapabilityFlags: u8 {
        const CAPFLAG_WINK = 0b00000001;
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
        match *self {
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

pub enum Command {
    Msg,
    Ping,
    Init,
    Error,
    Wink,
    Lock,
    Sync,
    Vendor { identifier: u8 },
}

pub enum Packet {
    Initialization {
        channel_id: ChannelId,
        command: Command,
        data: Vec<u8>,
        payload_len: usize,
    },
    Continuation {
        channel_id: ChannelId,
        sequence_number: u8,
        data: Vec<u8>,
    },
}

impl Packet {
    pub fn channel_id(&self) -> ChannelId {
        match self {
            &Packet::Initialization { channel_id, .. } => channel_id,
            &Packet::Continuation { channel_id, .. } => channel_id,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Packet, ()> {
        // TODO assert corerct bytes length
        let mut reader = Cursor::new(bytes);
        let channel_id = reader.read_u32::<BigEndian>().unwrap();
        let frame_type_byte = reader.read_u8().unwrap();
        if frame_type_byte & FRAME_TYPE_MASK == FRAME_TYPE_INIT {
            let command = match frame_type_byte {
                U2FHID_MSG => Command::Msg,
                U2FHID_PING => Command::Ping,
                U2FHID_INIT => Command::Init,
                U2FHID_ERROR => Command::Error,
                U2FHID_WINK => Command::Wink,
                U2FHID_LOCK => Command::Lock,
                U2FHID_SYNC => Command::Sync,
                id if id >= U2FHID_VENDOR_FIRST && id <= U2FHID_VENDOR_LAST => Command::Vendor {
                    identifier: id,
                },
                _ => return Err(()),
            };
            let payload_len = reader.read_u16::<BigEndian>().unwrap();
            let mut packet_data = Vec::with_capacity(INITIAL_PACKET_DATA_LEN);
            reader
                .read_exact(&mut packet_data[0..INITIAL_PACKET_DATA_LEN])
                .unwrap();
            Ok(Packet::Initialization {
                channel_id: channel_id,
                command: command,
                data: packet_data,
                payload_len: payload_len as usize,
            })
        } else {
            let sequence_number = frame_type_byte;
            let mut packet_data = Vec::with_capacity(CONTINUATION_PACKET_DATA_LEN);
            reader
                .read_exact(&mut packet_data[0..CONTINUATION_PACKET_DATA_LEN])
                .unwrap();
            Ok(Packet::Continuation {
                channel_id: channel_id,
                sequence_number: sequence_number,
                data: packet_data,
            })
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
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
                bytes.write_u32::<BigEndian>(channel_id).unwrap();

                // 4      1      CMD      Command identifier (bit 7 always set)
                let command_byte = match command {
                    Command::Msg => U2FHID_MSG,
                    Command::Ping => U2FHID_PING,
                    Command::Init => 0x06,
                    Command::Error => 0x3f,
                    Command::Wink => 0x08,
                    Command::Lock => 0x04,
                    Command::Sync => 0x3c,
                    Command::Vendor { identifier } => identifier,
                };
                bytes.push(command_byte);

                // 5      1      BCNTH    High part of payload length
                // 6      1      BCNTL    Low part of payload length
                bytes.write_u16::<BigEndian>(payload_len as u16).unwrap();

                // 7      (s-7)  DATA     Payload data (s is equal to the fixed packet size)
                bytes.extend_from_slice(&data);
            }
            Packet::Continuation {
                channel_id,
                sequence_number,
                data,
            } => {
                // Offset Length Mnemonic Description
                // 0      4      CID      Channel identifier
                bytes.write_u32::<BigEndian>(channel_id).unwrap();

                // 4      1      SEQ      Packet sequence 0x00..0x7f (bit 7 always cleared)
                assert!(sequence_number & FRAME_TYPE_MASK == FRAME_TYPE_CONT);
                bytes.push(sequence_number);

                // 5      (s-5)  DATA     Payload data (s is equal to the fixed packet size)
                bytes.extend_from_slice(&data);
            }
        }
        assert_eq!(bytes.len(), HID_REPORT_LEN);
        bytes
    }
}

pub enum RequestMessage {
    EncapsulatedRequest { data: Vec<u8> },
    Init { nonce: [u8; 8] },
    // Lock time in seconds 0..10. A value of 0 immediately releases the lock
    Lock { lock_time: u8 },
    Ping { data: Vec<u8> },
    Wink,
}

impl RequestMessage {
    pub fn decode(command: &Command, data: &[u8]) -> Result<RequestMessage, ()> {
        match command {
            &Command::Msg => Ok(RequestMessage::EncapsulatedRequest { data: data.to_vec() }),
            &Command::Ping => Ok(RequestMessage::Ping { data: data.to_vec() }),
            &Command::Init => {
                if data.len() != 8 {
                    Err(())
                } else {
                    let mut nonce = [0u8; 8];
                    nonce.copy_from_slice(&data[..]);
                    Ok(RequestMessage::Init { nonce: nonce })
                }
            }
            &Command::Wink => Ok(RequestMessage::Wink),
            &Command::Lock => {
                if data.len() != 1 {
                    Err(())
                } else {
                    Ok(RequestMessage::Lock { lock_time: data[0] })
                }
            }
            &Command::Sync => {
                // TODO
                Err(())
            }
            &Command::Error => Err(()),
            &Command::Vendor { .. } => Err(()),
        }
    }
}

#[derive(Debug)]
pub enum ResponseMessage {
    EncapsulatedResponse { data: Vec<u8> },
    Init {
        nonce: [u8; 8],
        channel_id: ChannelId,
        u2fhid_protocol_version: u8,
        major_device_version_number: u8,
        minor_device_version_number: u8,
        build_device_version_number: u8,
        capabilities: CapabilityFlags,
    },
    Ping { data: Vec<u8> },
    Error { code: ErrorCode },
    Wink,
}

impl ResponseMessage {
    pub fn to_packets(self, channel_id: ChannelId) -> Vec<Packet> {
        match self {
            ResponseMessage::EncapsulatedResponse { data } => {
                encode_response(channel_id, Command::Msg, &data)
            }
            ResponseMessage::Init {
                nonce,
                channel_id,
                u2fhid_protocol_version,
                major_device_version_number,
                minor_device_version_number,
                build_device_version_number,
                capabilities,
            } => {
                let mut data = Vec::with_capacity(17);
                data.extend_from_slice(&nonce);
                data.write_u32::<BigEndian>(channel_id).unwrap();
                data.push(u2fhid_protocol_version);
                data.push(major_device_version_number);
                data.push(minor_device_version_number);
                data.push(build_device_version_number);
                data.push(capabilities.bits);
                assert_eq!(data.len(), 17);
                encode_response(channel_id, Command::Init, &data)
            }
            ResponseMessage::Ping { data } => encode_response(channel_id, Command::Ping, &data),
            ResponseMessage::Error { code } => {
                let data = vec![code.to_byte()];
                encode_response(channel_id, Command::Error, &data)
            }
            ResponseMessage::Wink => encode_response(channel_id, Command::Wink, &[]),
        }
    }
}

fn encode_response(channel_id: ChannelId, command: Command, data: &[u8]) -> Vec<Packet> {
    let mut packets: Vec<Packet> = Vec::new();
    let split_index = cmp::min(data.len(), INITIAL_PACKET_DATA_LEN);
    let (initial, remaining) = data.split_at(split_index);
    packets.push(Packet::Initialization {
        channel_id: channel_id,
        command: command,
        payload_len: data.len(),
        data: initial.to_vec(),
    });
    for (i, chunk) in remaining.chunks(CONTINUATION_PACKET_DATA_LEN).enumerate() {
        packets.push(Packet::Continuation {
            channel_id: channel_id,
            sequence_number: i as u8,
            data: chunk.to_vec(),
        });
    }
    packets
}
