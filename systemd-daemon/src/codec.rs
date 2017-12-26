use std::{io, str};

use bincode::{self, Infinite, deserialize_from, serialize};
use bytes::{Buf, Bytes, BytesMut, IntoBuf};
use futures::{Poll, Sink, StartSend, Stream};
use serde::{Deserialize, Serialize};
use tokio_serde::{Deserializer, FramedRead, FramedWrite, Serializer};
use codec::{Encoder, Decoder};

#[derive(Debug, Error)]
pub enum Error {
    Io(io::Error),
    Serde(bincode::Error),
}

pub struct Bincode<L> {
    size_limit: L,
}

impl Bincode<L: SizeLimit> {
    pub fn new(size_limit: L) -> Bincode<L> { Bincode {
        size_limit: L
    }  }
}

impl<T, L> Deserializer<T> for Bincode<L>
where for<'de> T: Deserialize<'de>,
{
    type Error = Error;

    fn deserialize(&mut self, src: &Bytes) -> Result<T, Error> {
        deserialize_from(&mut src.into_buf().reader(), self.size_limit)
            .map_err(Error::Serde)
    }
}

impl<T> Serializer<T> for Bincode<T>
where T: Serialize
{
    type Error = io::Error;

    fn serialize(&mut self, item: &T) -> Result<BytesMut, io::Error> {
        serialize(item, self.size_limit)
            .map(Into::into)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error))
    }
}
