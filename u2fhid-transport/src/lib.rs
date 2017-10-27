#[macro_use]
extern crate futures;
extern crate u2f_core;
extern crate byteorder;
#[macro_use]
extern crate bitflags;

mod definitions;
mod protocol_state_machine;
mod send_all;

use std::mem;

use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream, stream};

use u2f_core::Request;
use definitions::*;
use protocol_state_machine::{Output, StateMachine};
use send_all::SendAll;

enum StreamState<S: Sink + Stream, E: Sized> {
    Unknown,
    Ready(S),
    SinkSending(SendAll<S, futures::stream::IterOk<std::vec::IntoIter<Packet>, E>>),
    SinkError(S, E),
    StreamSending(SendAll<S, futures::stream::IterOk<std::vec::IntoIter<Packet>, E>>),
    StreamError(S, E),
}

impl<S: Sink + Stream, E> StreamState<S, E> {
    fn take(&mut self) -> StreamState<S, E> {
        mem::replace(self, StreamState::Unknown)
    }
}

struct U2FHID<S: Sink + Stream, E> {
    state_machine: StateMachine,
    stream_state: StreamState<S, E>,
}

impl<S: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E>, E> U2FHID<S, E> {
    fn new(inner: S) -> U2FHID<S, E> {
        U2FHID {
            state_machine: StateMachine::new(),
            stream_state: StreamState::Ready(inner),
        }
    }

    fn try_take_inner_sink(&mut self) -> Poll<S, E> {
        match self.stream_state.take() {
            StreamState::Ready(inner) => Ok(Async::Ready(inner)),
            StreamState::SinkError(inner, error) => {
                self.stream_state = StreamState::Ready(inner);
                Err(error)
            }
            StreamState::SinkSending(mut future) => {
                match future.poll() {
                    Ok(Async::NotReady) => Ok(Async::NotReady),
                    Ok(Async::Ready((inner, _))) => Ok(Async::Ready(inner)),
                    Err(error) => Err(error),
                }
            }
            StreamState::StreamError(_, _) => Ok(Async::NotReady),
            StreamState::StreamSending(_) => Ok(Async::NotReady),
            StreamState::Unknown => panic!(),
        }
    }

    fn try_take_inner_stream(&mut self) -> Poll<S, E> {
        match self.stream_state.take() {
            StreamState::Ready(inner) => Ok(Async::Ready(inner)),
            StreamState::SinkError(_, _) => Ok(Async::NotReady),
            StreamState::SinkSending(_) => Ok(Async::NotReady),
            StreamState::StreamError(inner, error) => {
                self.stream_state = StreamState::Ready(inner);
                Err(error)
            }
            StreamState::StreamSending(mut future) => {
                match future.poll() {
                    Ok(Async::NotReady) => Ok(Async::NotReady),
                    Ok(Async::Ready((inner, _))) => Ok(Async::Ready(inner)),
                    Err(error) => Err(error),
                }
            }
            StreamState::Unknown => panic!(),
        }
    }

    fn send_response_message(
        message: ResponseMessage,
        channel_id: ChannelId,
        stream: S,
    ) -> SendAll<S, futures::stream::IterOk<std::vec::IntoIter<Packet>, E>> {
        let packets = message.to_packets(channel_id);
        send_all::new(stream, stream::iter_ok(packets))
    }
}

impl<
    S: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E> + 'static,
    E: 'static,
> Sink for U2FHID<S, E> {
    type SinkItem = ResponseMessage;
    type SinkError = S::SinkError;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        let sink = match self.try_take_inner_sink()? {
            Async::Ready(inner) => inner,
            Async::NotReady => return Ok(AsyncSink::NotReady(item)),
        };
        let channel_id = self.state_machine.transition_to_responding().unwrap(); // TODO no unwrap
        let packets = encode_response_message(channel_id, item).unwrap();
        let s = send_all::new(sink, stream::iter_ok(packets));
        self.stream_state = StreamState::SinkSending(s);
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        let mut inner = match self.try_take_inner_sink()? {
            Async::Ready(inner) => inner,
            Async::NotReady => return Ok(Async::NotReady),
        };
        inner.poll_complete()
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        let mut inner = match self.try_take_inner_sink()? {
            Async::Ready(inner) => inner,
            Async::NotReady => return Ok(Async::NotReady),
        };
        inner.close()
    }
}

impl<S: Stream<Item = Packet, Error = E> + Sink<SinkItem = Packet, SinkError = E>, E> Stream
    for U2FHID<S, E> {
    type Item = Request;
    type Error = <S as futures::Stream>::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            let mut stream = try_ready!(self.try_take_inner_stream());
            match stream.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(Some(packet))) => {
                    let res = self.state_machine.accept_packet(packet).unwrap();
                    match res {
                        Some(Output::Request(request)) => return Ok(Async::Ready(Some(request))),
                        Some(Output::ResponseMessage(message, channel_id)) => {
                            self.stream_state =
                                StreamState::StreamSending(
                                    Self::send_response_message(message, channel_id, stream),
                                );
                        }
                        None => {}
                    };
                }
                Ok(Async::Ready(None)) => return Ok(Async::Ready(None)),
                Err(error) => return Err(error),
            }
        }
    }
}

fn encode_response_message(
    channel_id: ChannelId,
    response_message: ResponseMessage,
) -> Result<Vec<Packet>, ()> {
    Ok(response_message.to_packets(channel_id))
}
