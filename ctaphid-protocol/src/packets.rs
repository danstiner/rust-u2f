use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde_derive::{Deserialize, Serialize};
use std::cmp;
use std::collections::VecDeque;
use std::io::{self, Cursor, Read};
use std::time::Duration;

pub const BROADCAST_CHANNEL_ID: ChannelId = ChannelId(0xffff_ffff);

const HID_REPORT_LEN: usize = 64;
const INITIAL_PACKET_DATA_LEN: usize = HID_REPORT_LEN - 7;
const CONTINUATION_PACKET_DATA_LEN: usize = HID_REPORT_LEN - 5;

const FRAME_TYPE_INIT: u8 = 0b1000_0000;
const FRAME_TYPE_CONT: u8 = 0b0000_0000;
const FRAME_TYPE_MASK: u8 = 0b1000_0000;

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

const CTAPHID_VENDOR_FIRST: u8 = FRAME_TYPE_INIT | 0x40; // First vendor defined command
const CTAPHID_VENDOR_LAST: u8 = FRAME_TYPE_INIT | 0x7f; // Last vendor defined command

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Packet {
    /// An initialization packet is the first packet sent in a message, it starts a new transaction.
    ///
    /// Offset  Length 	Mnemonic  Description
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
    /// Offset  Length 	Mnemonic  Description
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
        assert_eq!(bytes.len(), HID_REPORT_LEN + 1);
        let mut reader = Cursor::new(bytes);

        let hid_report_id = reader.read_u8().unwrap();
        assert_eq!(hid_report_id, 0x01); // TODO move validating the report it to a HID layer

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
                // Offset Length Mnemonic Description
                // 0      4      CID      Channel identifier
                channel_id.write(&mut bytes).unwrap();

                // 4      1      CMD      Command identifier (bit 7 always set)
                bytes.push(command.to_byte());

                // 5      1      BCNTH    High part of payload length
                // 6      1      BCNTL    Low part of payload length
                bytes.write_u16::<BigEndian>(*payload_len).unwrap();

                // 7      (s-7)  DATA     Payload data (s is equal to the fixed packet size)
                bytes.extend_from_slice(&data);
                for _ in data.len()..INITIAL_PACKET_DATA_LEN {
                    bytes.push(0u8);
                }
            }
            Packet::Continuation {
                channel_id,
                sequence_number,
                data,
            } => {
                // Offset Length Mnemonic Description
                // 0      4      CID      Channel identifier
                channel_id.write(&mut bytes).unwrap();

                // 4      1      SEQ      Packet sequence 0x00..0x7f (bit 7 always cleared)
                assert_eq!(sequence_number & FRAME_TYPE_MASK, FRAME_TYPE_CONT);
                bytes.push(*sequence_number);

                // 5      (s-5)  DATA     Payload data (s is equal to the fixed packet size)
                bytes.extend_from_slice(&data);
                for _ in data.len()..CONTINUATION_PACKET_DATA_LEN {
                    bytes.push(0u8);
                }
            }
        }
        assert_eq!(bytes.len(), HID_REPORT_LEN);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ChannelId(pub u32);

impl ChannelId {
    pub fn checked_add(self, number: u32) -> Option<ChannelId> {
        self.0.checked_add(number).map(|id| ChannelId(id))
    }

    pub fn write<W: WriteBytesExt>(&self, write: &mut W) -> io::Result<()> {
        write.write_u32::<BigEndian>(self.0)
    }
}

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
    fn from_byte(byte: u8) -> CommandType {
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

    fn to_byte(&self) -> u8 {
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

/// A CTAPHID_KEEPALIVE command SHOULD be sent at least every 100ms and whenever the status changes
/// while processing a CTAPHID_MSG. A KEEPALIVE sent by an authenticator does not constitute a
/// response and does therefore not end an ongoing transaction.
pub fn keepalive_interval() -> Duration {
    // We send twice every expected keep-alive interval to be on the safe side
    Duration::from_millis(50)
}

pub fn packet_timeout_duration() -> Duration {
    Duration::from_millis(500)
}

pub fn transaction_timeout_duration() -> Duration {
    Duration::from_millis(3000)
}
