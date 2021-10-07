#[macro_use]
extern crate bitflags;
extern crate byteorder;
#[macro_use]
extern crate futures;
extern crate itertools;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate slog;
extern crate slog_stdlog;
extern crate tokio_core;
extern crate u2f_core;

use std::collections::vec_deque::VecDeque;
use std::io;

pub use crate::definitions::Packet;
use crate::definitions::*;
use crate::protocol_state_machine::StateMachine;
use crate::segmenting_sink::{Segmenter, SegmentingSink};
use futures::{Async, AsyncSink, Future, Poll, Sink, Stream};
use slog::Drain;
use tokio_core::reactor::Handle;
use u2f_core::{Service, U2F};

mod definitions;
mod protocol_state_machine;
mod segmenting_sink;

struct PacketSegmenter;

impl Segmenter for PacketSegmenter {
    type Item = Response;
    type SegmentedItem = Packet;

    fn segment(&self, item: Self::Item) -> VecDeque<Self::SegmentedItem> {
        item.into_packets()
    }
}

pub struct U2FHID<T: Sink + Stream, S> {
    logger: slog::Logger,
    state_machine: StateMachine<S>,
    transport: SegmentingSink<T, PacketSegmenter>,
}

impl<T, E> U2FHID<T, U2F>
where
    T: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E>,
    E: From<io::Error>,
{
    pub fn bind_service<L: Into<Option<slog::Logger>>>(
        handle: Handle,
        transport: T,
        service: U2F,
        logger: L,
    ) -> U2FHID<T, U2F> {
        let logger = logger
            .into()
            .unwrap_or_else(|| slog::Logger::root(slog_stdlog::StdLog.fuse(), o!()));
        let state_machine_logger = logger.new(o!());
        U2FHID {
            logger,
            state_machine: StateMachine::new(service, handle, state_machine_logger),
            transport: SegmentingSink::new(transport, PacketSegmenter),
        }
    }
}

impl<T, S, E> Future for U2FHID<T, S>
where
    T: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E>,
    S: Service<
        Request = u2f_core::Request,
        Response = u2f_core::Response,
        Error = io::Error,
        Future = Box<dyn Future<Item = u2f_core::Response, Error = io::Error>>,
    >,
    E: From<io::Error>,
{
    type Item = ();
    type Error = E;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            trace!(self.logger, "Poll U2FHID");

            // Always tick the transport first
            // TODO self.transport.tick();

            try_ready!(self.transport.poll_complete());

            if let Some(response) = self.state_machine.step()? {
                trace!(self.logger, "Send response"; "channel_id" => &response.channel_id, "message" => &response.message);
                send(&mut self.transport, response)?;
                continue;
            }

            match try_ready!(self.transport.poll()) {
                Some(packet) => {
                    trace!(self.logger, "Got packet from transport"; "packet" => &packet);
                    if let Some(response) = self.state_machine.accept_packet(packet)? {
                        trace!(self.logger, "Send response"; "channel_id" => &response.channel_id, "message" => &response.message);
                        send(&mut self.transport, response)?;
                    }
                }
                None => {
                    // TODO close
                    return Ok(Async::Ready(()));
                }
            };
        }
    }
}

fn send<S: Sink>(s: &mut S, item: S::SinkItem) -> Result<(), S::SinkError> {
    match s.start_send(item)? {
        AsyncSink::Ready => Ok(()),
        AsyncSink::NotReady(_) => panic!(
            "sink reported itself as ready after `poll_ready` but was \
             then unable to accept a message"
        ),
    }
}
