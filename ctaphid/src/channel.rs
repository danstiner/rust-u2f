use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::io;

pub const BROADCAST_CHANNEL_ID: ChannelId = ChannelId(0xffff_ffff);
const MAX_CHANNEL_ID: ChannelId = ChannelId(BROADCAST_CHANNEL_ID.0 - 1);
const MIN_CHANNEL_ID: ChannelId = ChannelId(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Hash)]
pub struct ChannelId(pub u32);

impl ChannelId {
    pub fn new(channel_id: u32) -> Self {
        assert!(channel_id >= MIN_CHANNEL_ID.0 && channel_id <= MAX_CHANNEL_ID.0);
        Self(channel_id)
    }
    pub fn checked_add(self, number: u32) -> Option<ChannelId> {
        self.0.checked_add(number).and_then(|id| {
            // Do not overflow into the broadcast channel.
            if id == BROADCAST_CHANNEL_ID.0 {
                None
            } else {
                Some(ChannelId(id))
            }
        })
    }

    pub fn read<R: ReadBytesExt>(read: &mut R) -> io::Result<ChannelId> {
        Ok(ChannelId::new(read.read_u32::<BigEndian>()?))
    }

    pub fn write<W: WriteBytesExt>(&self, write: &mut W) -> io::Result<()> {
        write.write_u32::<BigEndian>(self.0)
    }
}

#[derive(Debug)]
pub struct Channels {
    next_allocation: ChannelId,
}

impl Channels {
    pub fn new() -> Channels {
        Channels {
            next_allocation: MIN_CHANNEL_ID,
        }
    }

    pub fn allocate(&mut self) -> Result<ChannelId, ()> {
        if self.next_allocation > MAX_CHANNEL_ID {
            Err(())
        } else {
            let allocation = self.next_allocation;
            self.next_allocation = self.next_allocation.checked_add(1).unwrap();
            Ok(allocation)
        }
    }

    pub fn is_valid(&self, channel_id: ChannelId) -> bool {
        let is_broadcast = channel_id == BROADCAST_CHANNEL_ID;
        let is_in_allocated_range =
            channel_id >= MIN_CHANNEL_ID && channel_id < self.next_allocation;
        is_broadcast || is_in_allocated_range
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_checked_add() {
        assert_eq!(ChannelId(1).checked_add(1), Some(ChannelId(2)));
        assert_eq!(ChannelId(0xffff_fffe).checked_add(1), None);
        assert_eq!(ChannelId(0xffff_fffe).checked_add(2), None);
    }

    #[test]
    fn channel_id_write() {
        let mut buf = Vec::new();
        ChannelId(0x01020304).write(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 3, 4]);
    }

    #[test]
    fn channels_broadcast_channel_is_valid() {
        let channels = Channels::new();
        assert!(channels.is_valid(BROADCAST_CHANNEL_ID));
    }

    #[test]
    fn channels_allocated_channel_is_valid() {
        let mut channels = Channels::new();
        let channel_id = channels.allocate().unwrap();
        assert!(channels.is_valid(channel_id));
    }
}
