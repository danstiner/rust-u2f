use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::collections::VecDeque;
use std::io::{Cursor, Read};

use crate::channel::ChannelId;
use crate::CommandType;

pub(crate) const HID_REPORT_LEN: usize = 64;
const INITIAL_PACKET_DATA_LEN: usize = HID_REPORT_LEN - 7;
const CONTINUATION_PACKET_DATA_LEN: usize = HID_REPORT_LEN - 5;

const FRAME_TYPE_INIT: u8 = 0b1000_0000;
const FRAME_TYPE_CONT: u8 = 0b0000_0000;
const FRAME_TYPE_MASK: u8 = 0b1000_0000;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Packet {
    /// An initialization packet is the first packet sent in a message, it starts a new transaction.
    ///
    /// Offset  Length  Mnemonic  Description
    /// ------------------------------------------------------------------------------
    /// 0       4       CID       Channel identifier
    /// 4       1       CMD       Command identifier (bit 7 always set)
    /// 5       1       BCNTH     High part of payload length
    /// 6       1       BCNTL     Low part of payload length
    /// 7       (s - 7) DATA      Payload data (s is equal to the fixed packet size)
    Initialization {
        channel_id: ChannelId,
        command: CommandType,
        data: Vec<u8>,
        payload_len: u16,
    },
    /// When a message does not fit in one packet, one or more continuation packets must be sent
    /// in strict assending order of sequence to complete the message transfer.
    ///
    /// Offset  Length  Mnemonic  Description
    /// ------------------------------------------------------------------------------
    /// 0       4       CID       Channel identifier
    /// 4       1       SEQ       Packet sequence 0x00..0x7f (bit 7 always cleared)
    /// 5       (s - 5) DATA      Payload data (s is equal to the fixed packet size)
    Continuation {
        channel_id: ChannelId,
        sequence_number: u8,
        data: Vec<u8>,
    },
}

impl Packet {
    pub fn channel_id(&self) -> ChannelId {
        match self {
            Packet::Initialization { channel_id, .. } => *channel_id,
            Packet::Continuation { channel_id, .. } => *channel_id,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Packet, ()> {
        assert_eq!(bytes.len(), HID_REPORT_LEN);
        let mut reader = Cursor::new(bytes);

        let channel_id = ChannelId(reader.read_u32::<BigEndian>().unwrap());
        let first_byte = reader.read_u8().unwrap();
        if first_byte & FRAME_TYPE_MASK == FRAME_TYPE_INIT {
            let command = CommandType::from_byte(first_byte);
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
                assert!(data.len() <= INITIAL_PACKET_DATA_LEN);

                // Offset Length Mnemonic Description
                // 0      4      CID      Channel identifier
                channel_id.write(&mut bytes).unwrap();

                // 4      1      CMD      Command identifier (bit 7 always set)
                bytes.push(command.to_byte() | FRAME_TYPE_INIT);

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
                assert!(data.len() <= CONTINUATION_PACKET_DATA_LEN);

                // Offset Length Mnemonic Description
                // 0      4      CID      Channel identifier
                channel_id.write(&mut bytes).unwrap();

                // 4      1      SEQ      Packet sequence 0x00..0x7f (bit 7 always cleared)
                assert_eq!(sequence_number & FRAME_TYPE_MASK, FRAME_TYPE_CONT);
                bytes.push(*sequence_number);

                // 5      (s-5)  DATA     Payload data (s is equal to the fixed packet size)
                bytes.extend_from_slice(data);
            }
        }

        // Zero-pad to expected report length
        bytes.resize(HID_REPORT_LEN, 0u8);
        bytes
    }

    pub(crate) fn encode_message(
        channel_id: ChannelId,
        command: CommandType,
        data: &[u8],
    ) -> VecDeque<Packet> {
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
}

#[cfg(test)]
mod tests {
    use crate::channel::BROADCAST_CHANNEL_ID;

    use super::*;

    #[test]
    fn packet_to_bytes_and_back() {
        let packet = Packet::Initialization {
            channel_id: ChannelId(0x12345678),
            command: CommandType::Ping,
            data: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
            ],
            payload_len: 0x08,
        };

        let decoded_packet = Packet::from_bytes(&packet.to_bytes()).unwrap();

        assert_eq!(decoded_packet, packet);
    }

    #[test]
    fn encode_message() {
        let packets = Vec::from(Packet::encode_message(
            BROADCAST_CHANNEL_ID,
            CommandType::Init,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
                66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
                87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
                106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
                122, 123, 124, 125, 126, 127,
            ],
        ));

        assert_eq!(
            packets,
            vec![
                Packet::Initialization {
                    channel_id: BROADCAST_CHANNEL_ID,
                    command: CommandType::Init,
                    data: vec![
                        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                    ],
                    payload_len: 127,
                },
                Packet::Continuation {
                    channel_id: BROADCAST_CHANNEL_ID,
                    data: vec![
                        58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
                        77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
                        96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
                        112, 113, 114, 115, 116,
                    ],
                    sequence_number: 0,
                },
                Packet::Continuation {
                    channel_id: BROADCAST_CHANNEL_ID,
                    data: vec![117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,],
                    sequence_number: 1,
                }
            ]
        );
    }
}
