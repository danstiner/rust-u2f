use std::io;

use futures::{Sink, Stream};

use crate::{Request, RequestMessageDecodeError, Response, definitions::Packet, framed::{Decoder, Encoder}};


/// Protocol for encoding/decoding the U2FHID protocol. HID USB transport.
/// 
/// U2F messages may be too long to fit in a single event on an HID USB transport.
/// So there is inherit complexity required to frame such messages as a series
/// of HID report using the extended length APDU encoding.
/// 
/// See https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html#protocol-structure-and-data-framing
pub struct U2fHidProtocol {
    // state_machine: StateMachine<S>,
}

impl U2fHidProtocol {
    pub fn new() -> Self {
        Self {
            // state_machine: StateMachine::new(),
        }
    }
}

impl Decoder for U2fHidProtocol {
    type Item = Packet;
    type Decoded = u2f_core::Request;
    type Error = io::Error; //RequestMessageDecodeError;

    fn decode(&mut self, item: &mut Self::Item) -> Result<Option<Self::Decoded>, Self::Error> {
        todo!()
    }
}

impl Encoder for U2fHidProtocol {
    type Item = u2f_core::Response;
    type Encoded = Packet;
    type Error = io::Error; //();

    fn encode(&mut self, item: &mut Self::Item) -> Result<Option<Self::Encoded>, Self::Error> {
        todo!()
    }
}
