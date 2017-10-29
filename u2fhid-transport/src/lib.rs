extern crate byteorder;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate futures;
extern crate tokio_core;
extern crate u2f_core;

mod buffer_one;
mod definitions;
mod protocol_state_machine;
mod send_all;

pub use definitions::Packet;

use std::mem;

use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream, stream};
use tokio_core::reactor::Handle;

use buffer_one::BufferOne;
use u2f_core::{Request, Service};
use definitions::*;
use protocol_state_machine::{Output, StateMachine};
use send_all::SendAll;

pub struct U2FHID<T: Sink + Stream, S> {
    service: S,
    state_machine: StateMachine,
    transport: BufferOne<T>,
}

impl<T, S, E> U2FHID<T, S>
where
    T: Sink<SinkItem = Packet, SinkError = E>
        + Stream<Item = Packet, Error = E>,
    S: Service,
    S::Error: Into<E>,
{
    pub fn bind_service(handle: &Handle, transport: T, service: S) -> U2FHID<T, S> {
        U2FHID {
            service: service,
            state_machine: StateMachine::new(),
            transport: BufferOne::new(transport),
        }
    }
}

// impl<I, S, E> Sink for U2FHID<I, S, E> where
//     I: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E> + 'static,
//     E: 'static,
//  {
//     type SinkItem = ResponseMessage;
//     type SinkError = I::SinkError;

//     fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
//         let sink = match self.try_take_inner_sink()? {
//             Async::Ready(inner) => inner,
//             Async::NotReady => return Ok(AsyncSink::NotReady(item)),
//         };
//         let channel_id = self.state_machine.transition_to_responding().unwrap(); // TODO no unwrap
//         let packets = encode_response_message(channel_id, item).unwrap();
//         let s = send_all::new(sink, stream::iter_ok(packets));
//         self.stream_state = StreamState::SinkSending(s);
//         Ok(AsyncSink::Ready)
//     }

//     fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
//         let mut inner = match self.try_take_inner_sink()? {
//             Async::Ready(inner) => inner,
//             Async::NotReady => return Ok(Async::NotReady),
//         };
//         inner.poll_complete()
//     }

//     fn close(&mut self) -> Poll<(), Self::SinkError> {
//         let mut inner = match self.try_take_inner_sink()? {
//             Async::Ready(inner) => inner,
//             Async::NotReady => return Ok(Async::NotReady),
//         };
//         inner.close()
//     }
// }

// impl<I, S, E> Stream
//     for U2FHID<I, S, E> where
//     I : Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E> {
//     type Item = Request;
//     type Error = <I as futures::Stream>::Error;

//     fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
//         loop {
//             let mut stream = try_ready!(self.try_take_inner_stream());
//             match stream.poll() {
//                 Ok(Async::NotReady) => return Ok(Async::NotReady),
//                 Ok(Async::Ready(Some(packet))) => {
//                     let res = self.state_machine.accept_packet(packet).unwrap();
//                     match res {
//                         Some(Output::Request(request)) => return Ok(Async::Ready(Some(request))),
//                         Some(Output::ResponseMessage(message, channel_id)) => {
//                             self.stream_state =
//                                 StreamState::StreamSending(
//                                     Self::send_response_message(message, channel_id, stream),
//                                 );
//                         }
//                         None => {}
//                     };
//                 }
//                 Ok(Async::Ready(None)) => return Ok(Async::Ready(None)),
//                 Err(error) => return Err(error),
//             }
//         }
//     }
// }

impl<T, S, E> Future for U2FHID<T, S>
where
    T: Sink<SinkItem = Packet, SinkError = E>
        + Stream<Item = Packet, Error = E>,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            // Always tick the transport first

            // poll for readiness on sink
            // if !self.check_out_body_stream() {
            //     break;
            // }

            // if let Async::Ready(frame) = try!(self.dispatch.get_mut().inner.transport().poll()) {
            //     try!(self.process_out_frame(frame));
            // } else {
            //     break;
            // }

            // check timeouts


            // poll read from transport stream

            // run state machine a step

            return Ok(Async::Ready(()));
        }
    }
}

fn encode_response_message(
    channel_id: ChannelId,
    response_message: ResponseMessage,
) -> Result<Vec<Packet>, ()> {
    Ok(response_message.to_packets(channel_id))
}

fn assert_send<S: Sink>(s: &mut S, item: S::SinkItem) -> Result<(), S::SinkError> {
    match try!(s.start_send(item)) {
        AsyncSink::Ready => Ok(()),
        AsyncSink::NotReady(_) => {
            panic!(
                "sink reported itself as ready after `poll_ready` but was \
                    then unable to accept a message"
            )
        }
    }
}
