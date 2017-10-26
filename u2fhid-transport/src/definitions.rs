use std::cmp;

use byteorder::{BigEndian, WriteBytesExt};

pub const MAJOR_DEVICE_VERSION_NUMBER: u8 = 0;
pub const MINOR_DEVICE_VERSION_NUMBER: u8 = 1;
pub const BUILD_DEVICE_VERSION_NUMBER: u8 = 0;

pub const U2FHID_PROTOCOL_VERSION: u8 = 2;

const HID_REPORT_SIZE: usize = 64;
const INITIAL_PACKET_DATA_MAX_LEN: usize = HID_REPORT_SIZE - 7;
const CONTINUATION_PACKET_DATA_MAX_LEN: usize = HID_REPORT_SIZE - 5;

pub type ChannelId = u32;

bitflags! {
    pub struct CapabilityFlags: u8 {
        const CAPFLAG_WINK = 0b00000001;
    }
}

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
                    nonce.copy_from_slice(&data[0..7]);
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
            &Command::Error => Err(()),
            &Command::Vendor { .. } => Err(()),
        }
    }
}

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
    let split_index = cmp::min(data.len(), INITIAL_PACKET_DATA_MAX_LEN);
    let (initial, remaining) = data.split_at(split_index);
    packets.push(Packet::Initialization {
        channel_id: channel_id,
        command: command,
        payload_len: data.len(),
        data: initial.to_vec(),
    });
    for (i, chunk) in remaining
        .chunks(CONTINUATION_PACKET_DATA_MAX_LEN)
        .enumerate()
    {
        packets.push(Packet::Continuation {
            channel_id: channel_id,
            sequence_number: i as u8,
            data: chunk.to_vec(),
        });
    }
    packets
}
