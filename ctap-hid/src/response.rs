use byteorder::ReadBytesExt;
use std::{
    collections::VecDeque,
    io::{Cursor, Read, Write},
};
use thiserror::Error;

use crate::{channel::ChannelId, packet::Packet, CapabilityFlags, CommandType, ErrorCode};

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct ResponseMessage {
    pub channel_id: ChannelId,
    pub response: Response,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveStatus {
    Processing = 0x01,
    UserPresenceNeeded = 0x02,
}

#[allow(dead_code)]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResponseDecodeError {
    #[error("Invalid command: {0:?}")]
    InvalidCommand(CommandType),
}

#[allow(dead_code)]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResponseMessageDecodeError {
    #[error("Incomplete message")]
    Incomplete,

    #[error("InvalidFirstPacket")]
    InvalidFirstPacket,

    #[error("InvalidPacketOrder")]
    InvalidPacketOrder,

    #[error("Response decode error: {0:?}")]
    ResponseDecodeError(#[from] ResponseDecodeError),
}

impl Response {
    #[allow(unused)]
    pub fn decode(command: CommandType, data: &[u8]) -> Result<Response, ResponseDecodeError> {
        match command {
            CommandType::Msg => Ok(Response::Msg {
                data: data.to_vec(),
            }),
            CommandType::Ping => Ok(Response::Ping {
                data: data.to_vec(),
            }),
            CommandType::Init => {
                assert_eq!(data.len(), 17);
                let mut cursor = Cursor::new(data);
                let mut nonce = [0u8; 8];
                cursor.read_exact(&mut nonce).unwrap();
                Ok(Response::Init {
                    nonce,
                    new_channel_id: ChannelId::read(&mut cursor).unwrap(),
                    ctaphid_protocol_version: cursor.read_u8().unwrap(),
                    major_device_version_number: cursor.read_u8().unwrap(),
                    minor_device_version_number: cursor.read_u8().unwrap(),
                    build_device_version_number: cursor.read_u8().unwrap(),
                    capabilities: CapabilityFlags::from_bits_truncate(cursor.read_u8().unwrap()),
                })
            }
            CommandType::Cbor => Ok(Response::Cbor {
                data: data.to_vec(),
            }),
            CommandType::Cancel => todo!(),
            CommandType::KeepAlive => todo!(),
            CommandType::Wink => Ok(Response::Wink),
            CommandType::Lock => Err(ResponseDecodeError::InvalidCommand(command)),
            CommandType::Error => Err(ResponseDecodeError::InvalidCommand(command)),
            CommandType::Vendor { .. } => Err(ResponseDecodeError::InvalidCommand(command)),
            CommandType::Unknown { .. } => {
                // The Fido v2.0 specification is backwards compatible with U2F
                // authenticators if they responded to unknown messages with
                // the error message InvalidCommand (0x01).
                // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#interoperating-with-ctap1-u2f-authenticators
                Err(ResponseDecodeError::InvalidCommand(command))
            }
        }
    }
}

impl ResponseMessage {
    #[cfg(test)]
    pub fn decode(packets: &[Packet]) -> Result<Self, ResponseMessageDecodeError> {
        if packets.is_empty() {
            return Err(ResponseMessageDecodeError::Incomplete);
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
                payload.extend_from_slice(data);
                (*channel_id, *command, *payload_len as usize)
            }
            Packet::Continuation { .. } => {
                return Err(ResponseMessageDecodeError::InvalidFirstPacket)
            }
        };

        for packet in packets[1..].iter() {
            match packet {
                Packet::Initialization { .. } => {
                    return Err(ResponseMessageDecodeError::InvalidPacketOrder);
                }
                Packet::Continuation {
                    channel_id,
                    data,
                    sequence_number,
                } => {
                    assert_eq!(*channel_id, packets[0].channel_id());
                    assert_eq!(*sequence_number, expected_sequence_number);
                    expected_sequence_number += 1;

                    payload.extend_from_slice(data);
                }
            }
        }

        let response = Response::decode(command, &payload[0..payload_len])?;

        Ok(Self {
            channel_id,
            response,
        })
    }

    pub fn to_packets(&self) -> VecDeque<Packet> {
        let channel_id = self.channel_id;
        match &self.response {
            Response::Ping { data } => Packet::encode_message(channel_id, CommandType::Ping, data),
            Response::Msg { data } => Packet::encode_message(channel_id, CommandType::Msg, data),
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
                data.write_all(nonce).unwrap();
                new_channel_id.write(&mut data).unwrap();
                data.push(*ctaphid_protocol_version);
                data.push(*major_device_version_number);
                data.push(*minor_device_version_number);
                data.push(*build_device_version_number);
                data.push(capabilities.bits);
                assert_eq!(data.len(), 17);
                Packet::encode_message(channel_id, CommandType::Init, &data)
            }
            Response::Cbor { data } => Packet::encode_message(channel_id, CommandType::Cbor, data),
            Response::KeepAlive { status: _ } => {
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

#[cfg(test)]
mod tests {
    use crate::CommandType;

    use super::*;

    #[test]
    fn response_message_encode_multi_packet_msg() {
        assert_eq!(
            ResponseMessage {
                channel_id: ChannelId(1),
                response: Response::Msg {
                    data: (0u8..128).collect()
                }
            }
            .to_packets(),
            vec![
                Packet::Initialization {
                    channel_id: ChannelId(1),
                    command: CommandType::Msg,
                    data: (0u8..57).collect(),
                    payload_len: 128,
                },
                Packet::Continuation {
                    channel_id: ChannelId(1),
                    sequence_number: 0,
                    data: (57u8..116).collect()
                },
                Packet::Continuation {
                    channel_id: ChannelId(1),
                    sequence_number: 1,
                    data: (116u8..128).collect()
                }
            ]
        );
    }
}
