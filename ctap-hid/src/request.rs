use std::{collections::VecDeque, time::Duration};
use thiserror::Error;

use crate::{channel::ChannelId, packet::Packet, CommandType, COMMAND_INIT_DATA_LEN};

#[derive(Debug, PartialEq)]
#[allow(dead_code)]
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

#[derive(Debug, PartialEq)]
pub struct RequestMessage {
    pub channel_id: ChannelId,
    pub request: Request,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveStatus {
    Processing = 0x01,
    UserPresenceNeeded = 0x02,
}

#[derive(Debug, Error, PartialEq)]
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

#[derive(Debug, Error, PartialEq)]
pub enum RequestDecodeError {
    #[error("Payload length ({actual_len}) longer than expected ({expected_len})")]
    PayloadLength {
        expected_len: usize,
        actual_len: usize,
    },

    #[error("Invalid command: {0:?}")]
    InvalidCommand(CommandType),
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
            CommandType::Lock => Err(RequestDecodeError::InvalidCommand(command)),
            CommandType::Error => Err(RequestDecodeError::InvalidCommand(command)),
            CommandType::Vendor { .. } => Err(RequestDecodeError::InvalidCommand(command)),
            CommandType::Unknown { .. } => {
                // The Fido v2.0 specification is backwards compatible with U2F
                // authenticators if they responded to unknown messages with
                // the error message InvalidCommand (0x01).
                // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#interoperating-with-ctap1-u2f-authenticators
                Err(RequestDecodeError::InvalidCommand(command))
            }
        }
    }
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

    pub fn to_packets(&self) -> VecDeque<Packet> {
        let channel_id = self.channel_id;
        match &self.request {
            Request::Ping { data } => Packet::encode_message(channel_id, CommandType::Ping, data),
            Request::Msg { data } => Packet::encode_message(channel_id, CommandType::Msg, data),
            Request::Init { nonce } => Packet::encode_message(channel_id, CommandType::Init, nonce),
            Request::Cbor { data } => Packet::encode_message(channel_id, CommandType::Cbor, data),
            Request::Cancel => Packet::encode_message(channel_id, CommandType::Error, &[]),
            Request::Lock { lock_time } => {
                Packet::encode_message(channel_id, CommandType::Lock, &[lock_time.as_secs() as u8])
            }
            Request::Wink => Packet::encode_message(channel_id, CommandType::Wink, &[]),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{CommandType, COMMAND_INIT_DATA_LEN};

    use super::*;

    #[test]
    fn request_decode_ping() {
        assert_eq!(
            Request::decode(CommandType::Ping, &vec![0, 1, 2, 3, 4, 5, 6, 7]),
            Ok(Request::Ping {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7]
            })
        );
    }

    #[test]
    fn request_decode_msg() {
        assert_eq!(
            Request::decode(CommandType::Msg, &vec![0, 1, 2, 3, 4, 5, 6, 7]),
            Ok(Request::Msg {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7]
            })
        );
    }

    #[test]
    fn request_decode_init() {
        assert_eq!(
            Request::decode(CommandType::Init, &vec![0, 1, 2, 3, 4, 5, 6, 7]),
            Ok(Request::Init {
                nonce: [0, 1, 2, 3, 4, 5, 6, 7]
            })
        );
    }

    #[test]
    fn request_decode_init_invalid_data() {
        assert_eq!(
            Request::decode(CommandType::Init, &vec![0, 1]),
            Err(RequestDecodeError::PayloadLength {
                expected_len: COMMAND_INIT_DATA_LEN,
                actual_len: 2,
            })
        );
    }

    #[test]
    fn request_decode_cbor() {
        assert_eq!(
            Request::decode(CommandType::Cbor, &vec![0, 1, 2, 3, 4, 5, 6, 7]),
            Ok(Request::Cbor {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7]
            })
        );
    }

    #[test]
    fn request_decode_wink() {
        assert_eq!(
            Request::decode(CommandType::Wink, &vec![]),
            Ok(Request::Wink)
        );
    }

    #[test]
    fn request_message_decode_init() {
        assert_eq!(
            RequestMessage::decode(&vec![Packet::Initialization {
                channel_id: crate::channel::BROADCAST_CHANNEL_ID,
                command: CommandType::Init,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7],
                payload_len: 8,
            }]),
            Ok(RequestMessage {
                channel_id: crate::channel::BROADCAST_CHANNEL_ID,
                request: Request::Init {
                    nonce: [0, 1, 2, 3, 4, 5, 6, 7]
                }
            })
        );
    }

    #[test]
    fn request_message_decode_multi_packet_msg() {
        assert_eq!(
            RequestMessage::decode(&vec![
                Packet::Initialization {
                    channel_id: ChannelId(1),
                    command: CommandType::Msg,
                    data: vec![0, 1, 2],
                    payload_len: 8,
                },
                Packet::Continuation {
                    channel_id: ChannelId(1),
                    sequence_number: 0,
                    data: vec![3, 4, 5]
                },
                Packet::Continuation {
                    channel_id: ChannelId(1),
                    sequence_number: 1,
                    data: vec![6, 7]
                }
            ]),
            Ok(RequestMessage {
                channel_id: ChannelId(1),
                request: Request::Msg {
                    data: vec![0, 1, 2, 3, 4, 5, 6, 7]
                }
            })
        );
    }
}
