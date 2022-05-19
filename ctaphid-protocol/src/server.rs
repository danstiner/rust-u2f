use std::{
    collections::VecDeque,
    fmt, io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Future, Sink, Stream};
use pin_project::pin_project;
use tracing::{error, trace};

use crate::{api::CtapHidApi, message::ResponseMessage, packet::Packet, protocol::Protocol};

#[pin_project]
pub struct Server<T, Svc, E> {
    protocol: Protocol<Svc, E>,
    send_buffer: Option<VecDeque<Packet>>,
    #[pin]
    transport: T,
    _marker: PhantomData<E>,
}

impl<T, Svc, SinkE, StreamE, E> Server<T, Svc, E>
where
    T: Sink<Packet, Error = SinkE> + Stream<Item = Result<Packet, StreamE>> + Unpin,
    Svc: CtapHidApi<Error = E> + 'static,
    Svc::Error: 'static,
    E: From<SinkE> + From<StreamE> + From<Svc::Error> + From<io::Error> + 'static,
{
    pub fn new(transport: T, service: Svc) -> Server<T, Svc, E> {
        Server {
            protocol: Protocol::new(service),
            transport,
            send_buffer: None,
            _marker: PhantomData,
        }
    }

    fn buffer_send_packet(&mut self, packet: Packet) {
        debug_assert!(self.send_buffer.is_none());
        trace!(
            channel_id = ?packet.channel_id(),
            "CtapHidServer::buffer_send_packet: {:?}", packet
        );
        self.send_buffer = Some(VecDeque::from(vec![packet]));
    }
}

impl<T, Svc, SinkE, StreamE, E> Future for Server<T, Svc, E>
where
    T: Sink<Packet, Error = SinkE> + Stream<Item = Result<Packet, StreamE>> + Unpin,
    Svc: CtapHidApi<Error = E> + Clone + 'static,
    Svc::Error: 'static,
    E: From<SinkE> + From<StreamE> + From<Svc::Error> + From<io::Error> + fmt::Debug + 'static,
{
    type Output = Result<(), E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        trace!("CtapHidServer::poll: start");
        let this = &mut *self;
        loop {
            // First flush any buffered packets
            if let Some(mut buffer) = this.send_buffer.take() {
                trace!(
                    "CtapHidServer::poll: {} packets in send buffer",
                    buffer.len()
                );

                // Ensure transport is ready to send a packet, otherwise place back the buffer
                match Pin::new(&mut this.transport).poll_ready(cx)? {
                    Poll::Ready(()) => {}
                    Poll::Pending => {
                        trace!("CtapHidServer::poll: Transport not ready");
                        this.send_buffer = Some(buffer);
                        return Poll::Pending;
                    }
                }

                match buffer.pop_front() {
                    Some(packet) => {
                        // Send first packet and place back the remaining buffer
                        trace!(
                            "CtapHidServer::poll: Starting send of a packet, remaining: {}",
                            buffer.len()
                        );
                        this.send_buffer = Some(buffer);
                        Pin::new(&mut this.transport).start_send(packet)?;
                        continue;
                    }
                    None => {
                        // Have begun sending all buffer have been sent, flush before clearing entirely
                        trace!("CtapHidServer::poll: Started send of all buffered packets, flushing transport");
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
            trace!("CtapHidServer::poll: protocol.poll_next");
            match Pin::new(&mut this.protocol).poll_next(cx) {
                Poll::Ready(Some(packet)) => {
                    this.buffer_send_packet(packet);
                    continue;
                }
                Poll::Ready(None) => {
                    error!("CtapHidServer::poll: protocol.poll_next returned None");
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    trace!("CtapHidServer::poll: protocol.poll_next pending");
                }
            };

            // At this point there are no responses waiting to send, check for input
            trace!("CtapHidServer::poll: protocol.poll_ready");
            match ready!(Pin::new(&mut this.protocol).poll_ready(cx)) {
                Ok(()) => {
                    trace!("CtapHidServer::poll: protocol.poll_ready was ready");
                    match ready!(Pin::new(&mut this.transport).poll_next(cx)?) {
                        Some(packet) => {
                            trace!(?packet, "Got packet from transport");
                            Pin::new(&mut this.protocol).start_send(packet)?;
                        }
                        None => todo!("it's closing time"),
                    };
                }
                Err(err) => return Poll::Ready(Err(err.into())),
            }
        }
    }
}
