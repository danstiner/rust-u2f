use std::{
    collections::VecDeque,
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Future, Sink, Stream};
use pin_project::pin_project;
use tracing::trace;
use u2f_core::Service;

use crate::{protocol_state_machine::StateMachine, Packet, Response};

#[pin_project]
pub struct U2fHidServer<T, Svc, E> {
    state_machine: StateMachine<Svc, E>,
    send_buffer: Option<VecDeque<Packet>>,
    #[pin]
    transport: T,
    _marker: PhantomData<E>,
}

impl<T, Svc, SinkE, StreamE, E> U2fHidServer<T, Svc, E>
where
    T: Sink<Packet, Error = SinkE> + Stream<Item = Result<Packet, StreamE>> + Unpin,
    Svc: Service<u2f_core::Request, Response = u2f_core::Response>,
    Svc::Future: 'static,
    E: From<SinkE> + From<StreamE> + From<Svc::Error> + From<io::Error> + 'static,
{
    pub fn new(transport: T, service: Svc) -> U2fHidServer<T, Svc, E> {
        U2fHidServer {
            state_machine: StateMachine::new(service),
            transport,
            send_buffer: None,
            _marker: PhantomData,
        }
    }

    fn buffer_send(&mut self, response: Response) {
        debug_assert!(self.send_buffer.is_none());
        trace!(
            channel_id = ?response.channel_id,
            "U2fHidServer::buffer_send: {:?}", response.message
        );
        self.send_buffer = Some(response.to_packets());
    }
}

impl<T, S, SinkE, StreamE, E> Future for U2fHidServer<T, S, E>
where
    T: Sink<Packet, Error = SinkE> + Stream<Item = Result<Packet, StreamE>> + Unpin,
    S: Service<u2f_core::Request, Response = u2f_core::Response>,
    S::Future: 'static,
    E: From<SinkE> + From<StreamE> + From<S::Error> + From<io::Error> + 'static,
{
    type Output = Result<(), E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        loop {
            // First flush any buffered packets
            if let Some(mut buffer) = this.send_buffer.take() {
                trace!(
                    "U2fHidServer::poll: {} packets in send buffer",
                    buffer.len()
                );

                // Ensure transport is ready to send a packet, otherwise place back the buffer
                match Pin::new(&mut this.transport).poll_ready(cx)? {
                    Poll::Ready(()) => {}
                    Poll::Pending => {
                        trace!("U2fHidServer::poll: Transport not ready");
                        this.send_buffer = Some(buffer);
                        return Poll::Pending;
                    }
                }

                match buffer.pop_front() {
                    Some(packet) => {
                        // Send first packet and place back the remaining buffer
                        trace!(
                            "U2fHidServer::poll: Starting send of a packet, remaining: {}",
                            buffer.len()
                        );
                        this.send_buffer = Some(buffer);
                        Pin::new(&mut this.transport).start_send(packet)?;
                        continue;
                    }
                    None => {
                        // Have begun sending all buffer have been sent, flush before clearing entirely
                        trace!("U2fHidServer::poll: Started send of all buffered packets, flushing transport");
                        match Pin::new(&mut this.transport).poll_flush(cx) {
                            Poll::Ready(Ok(())) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                            Poll::Pending => {
                                // Putting back will cause the next poll() to try flushing again
                                this.send_buffer = Some(buffer);
                                return Poll::Pending;
                            }
                        }
                    }
                }
            }

            // At this point the packet buffer is empty, check if there is a new response to send
            if let Some(response) = ready!(this.state_machine.poll_next(cx))? {
                this.buffer_send(response);
                continue;
            }

            // At this point there are no responses waiting to send, check for input
            match ready!(Pin::new(&mut this.transport).poll_next(cx)?) {
                Some(packet) => {
                    trace!(?packet, "Got packet from transport");
                    if let Some(response) = this.state_machine.accept_packet(packet, cx)? {
                        this.buffer_send(response);
                    }
                }
                None => todo!("it's closing time"),
            };
        }
    }
}
