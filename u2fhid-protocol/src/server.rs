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
pub struct U2fHidServer<T, S, E> {
    state_machine: StateMachine<S, E>,
    send_buffer: Option<VecDeque<Packet>>,
    #[pin]
    transport: T,
    _marker: PhantomData<E>,
}

impl<T, S, SinkE, StreamE, E> U2fHidServer<T, S, E>
where
    T: Sink<Packet, Error = SinkE> + Stream<Item = Result<Packet, StreamE>> + Unpin,
    S: Service<u2f_core::Request, Response = u2f_core::Response>,
    S::Future: 'static,
    E: From<SinkE> + From<StreamE> + From<S::Error> + From<io::Error> + 'static,
{
    pub fn new(transport: T, service: S) -> U2fHidServer<T, S, E> {
        U2fHidServer {
            state_machine: StateMachine::new(service),
            transport,
            send_buffer: None,
            _marker: PhantomData,
        }
    }

    fn queue_send(&mut self, response: Response) {
        debug_assert!(self.send_buffer.is_none());
        trace!(
            channel_id = ?response.channel_id,
            message = ?response.message,
            "U2fHidServer:queue_send: Queuing packetized response"
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
        trace!("U2fHidServer::poll");
        let this = &mut *self;
        loop {
            if let Some(mut buffer) = this.send_buffer.take() {
                trace!("U2fHidServer::poll: Sending buffered packets");

                // Ensure transport is ready to send a packet, otherwise place back the buffer
                match Pin::new(&mut this.transport).poll_ready(cx)? {
                    Poll::Ready(()) => {}
                    Poll::Pending => {
                        this.send_buffer = Some(buffer);
                        return Poll::Pending;
                    }
                }

                match buffer.pop_front() {
                    Some(packet) => {
                        // Send first packet and place back the remaining buffer
                        this.send_buffer = Some(buffer);
                        Pin::new(&mut this.transport).start_send(packet)?;
                        continue;
                    }
                    None => {
                        // All packets in the buffer have been sent, flush before clearing entirely
                        match Pin::new(&mut this.transport).poll_flush(cx) {
                            Poll::Ready(Ok(())) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                            Poll::Pending => {
                                this.send_buffer = Some(buffer);
                                return Poll::Pending;
                            }
                        }
                    }
                }
            }

            if let Some(response) = ready!(this.state_machine.poll_next(cx))? {
                this.queue_send(response);
                continue;
            }

            match ready!(Pin::new(&mut this.transport).poll_next(cx)?) {
                Some(packet) => {
                    trace!(?packet, "Got packet from transport");
                    if let Some(response) = this.state_machine.accept_packet(packet, cx)? {
                        this.queue_send(response);
                    }
                }
                None => todo!("it's closing time"),
            };
        }
    }
}
