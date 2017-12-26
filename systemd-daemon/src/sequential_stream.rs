use std::io;

use bincode::{serialize, deserialize, Infinite};
use bytes::{BytesMut, BufMut};

trait SequentialStreamCodec {
    type In;
    type Out;
    type Error;
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Self::In, Self::Error>;
    fn encode(&mut self, msg: Self::Out, buf: &mut BytesMut);
}

struct SocketCodec;

impl SequentialStreamCodec for SocketCodec {
    type In = Request;
    type Out = Response;
    type Error = io::Error;
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Self::In, Self::Error> {
        Ok(deserialize(&buf[..]).unwrap())
    }
    fn encode(&mut self, msg: Self::Out, buf: &mut BytesMut) {
        let encoded: Vec<u8> = serialize(&msg, Infinite).unwrap();
        buf.reserve(encoded.len());
        buf.put(encoded);
    }
}
