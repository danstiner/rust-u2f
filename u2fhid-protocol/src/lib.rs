extern crate byteorder;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate slog;
extern crate slog_stdlog;
extern crate tokio_core;
extern crate u2f_core;

mod definitions;
mod protocol_state_machine;
mod segmenting_sink;

pub use definitions::Packet;

use std::io;
use std::collections::vec_deque::VecDeque;

use futures::{Async, AsyncSink, Future, Poll, Sink, Stream};
use slog::Drain;
use tokio_core::reactor::Handle;

use definitions::*;
use protocol_state_machine::StateMachine;
use segmenting_sink::{Segmenter, SegmentingSink};
use u2f_core::{Service, U2F};

struct PacketSegmenter;

impl Segmenter for PacketSegmenter {
    type Item = Response;
    type SegmentedItem = Packet;

    fn segment(&self, item: Self::Item) -> VecDeque<Self::SegmentedItem> {
        item.to_packets()
    }
}

pub struct U2FHID<T: Sink + Stream, S> {
    logger: slog::Logger,
    state_machine: StateMachine<S>,
    transport: SegmentingSink<T, PacketSegmenter>,
}

impl<T> U2FHID<T, U2F>
where
    T: Sink<SinkItem = Packet, SinkError = io::Error>
        + Stream<Item = Packet, Error = io::Error>,
{
    pub fn bind_service<L: Into<Option<slog::Logger>>>(
        handle: &Handle,
        transport: T,
        service: U2F,
        logger: L,
    ) -> U2FHID<T, U2F> {
        let logger = logger.into().unwrap_or(slog::Logger::root(
            slog_stdlog::StdLog.fuse(),
            o!(),
        ));
        let state_machine_logger = logger.new(o!());
        U2FHID {
            logger: logger,
            state_machine: StateMachine::new(service, handle.clone(), state_machine_logger),
            transport: SegmentingSink::new(transport, PacketSegmenter),
        }
    }
}

impl<T, S> Future for U2FHID<T, S>
where
    T: Sink<SinkItem = Packet, SinkError = io::Error>
        + Stream<Item = Packet, Error = io::Error>,
    S: Service<
        Request = u2f_core::Request,
        Response = u2f_core::Response,
        Error = io::Error,
        Future = Box<
            Future<
                Item = u2f_core::Response,
                Error = io::Error,
            >,
        >,
    >,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            trace!(self.logger, "Poll U2FHID");

            // Always tick the transport first
            // TODO self.transport.tick();

            trace!(self.logger, "Ensure sink is ready");
            try_ready!(self.transport.poll_complete());

            trace!(self.logger, "Try to step state machine");
            if let Some(response) = self.state_machine.step()? {
                debug!(self.logger, "Send response"; "channel_id" => &response.channel_id, "message" => &response.message);
                assert_send(&mut self.transport, response)?;
                continue;
            }

            trace!(self.logger, "Poll read from transport stream");
            match try_ready!(self.transport.poll()) {
                Some(packet) => {
                    trace!(self.logger, "Run state machine with read packet"; "packet" => &packet);
                    match self.state_machine.accept_packet(packet)? {
                        Some(response) => {
                            debug!(self.logger, "Send response"; "channel_id" => &response.channel_id, "message" => &response.message);
                            assert_send(&mut self.transport, response)?;
                        }
                        None => {}
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
