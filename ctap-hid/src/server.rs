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

use crate::{api::CtapHidApi, packet::Packet, protocol::Protocol};

#[pin_project]
pub struct Server<'a, T, Svc, E> {
    protocol: Protocol<'a, Svc, E>,
    send_buffer: Option<VecDeque<Packet>>,
    #[pin]
    transport: T,
    _marker: PhantomData<E>,
}

impl<'a, T, Svc, SinkE, StreamE, E> Server<'a, T, Svc, E>
where
    T: Sink<Packet, Error = SinkE> + Stream<Item = Result<Packet, StreamE>> + Unpin,
    Svc: CtapHidApi<Error = E> + 'a,
    E: From<SinkE> + From<StreamE> + From<Svc::Error> + From<io::Error> + fmt::Debug + 'static,
{
    pub fn new(transport: T, service: Svc) -> Server<'a, T, Svc, E> {
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

impl<'a, T, Svc, SinkE, StreamE, E> Future for Server<'a, T, Svc, E>
where
    T: Sink<Packet, Error = SinkE> + Stream<Item = Result<Packet, StreamE>> + Unpin,
    Svc: CtapHidApi<Error = E> + 'a,
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
                        None => {
                            trace!("it's closing time");
                            return Poll::Ready(Ok(()));
                        }
                    };
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use std::{
        sync::{Arc, Mutex},
        task::Waker,
        time::Duration,
    };

    use async_trait::async_trait;
    use pin_project::pin_project;
    use tokio::{join, time::sleep};

    use crate::{
        api::VersionInfo,
        channel::{ChannelId, BROADCAST_CHANNEL_ID},
        request::{Request, RequestMessage},
        response::{Response, ResponseMessage},
        CapabilityFlags,
    };

    use super::*;

    #[derive(Default)]
    struct FakeTransportInner {
        input: Vec<Option<Result<Packet, io::Error>>>,
        input_waker: Option<Waker>,
        output: Vec<Packet>,
    }

    impl FakeTransportInner {
        fn feed_next(&mut self, value: Option<Result<Packet, io::Error>>) {
            self.input.push(value);
            if let Some(waker) = self.input_waker.take() {
                waker.wake();
            }
        }
    }

    #[pin_project]
    #[derive(Default)]
    struct FakeTransport {
        state: Arc<Mutex<FakeTransportInner>>,
    }

    impl Sink<Packet> for FakeTransport {
        type Error = io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Packet) -> Result<(), Self::Error> {
            let this = self.project();
            let mut state = this.state.lock().unwrap();
            state.output.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            todo!()
        }
    }

    impl Stream for FakeTransport {
        type Item = Result<Packet, io::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.project();
            let mut state = this.state.lock().unwrap();
            match state.input.pop() {
                Some(v) => Poll::Ready(v),
                None => {
                    state.input_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }
    }

    struct FakeService;

    #[async_trait(?Send)]
    impl CtapHidApi for FakeService {
        type Error = io::Error;

        fn version(&self) -> Result<VersionInfo, Self::Error> {
            Ok(VersionInfo {
                major: 1,
                minor: 2,
                build: 3,
                capabilities: CapabilityFlags::WINK,
            })
        }
        async fn wink(&self) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn msg(&self, _msg: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
            Ok(vec!['m' as u8, 's' as u8, 'g' as u8])
        }
        async fn cbor(&self, _cbor: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
            Ok(vec!['c' as u8, 'b' as u8, 'o' as u8, 'r' as u8])
        }
    }

    #[tokio::test]
    async fn new() {
        Server::new(FakeTransport::default(), FakeService);
    }

    #[tokio::test]
    async fn close() {
        let transport = FakeTransport::default();
        let service = FakeService;
        let s = Arc::clone(&transport.state);
        let server = Server::new(transport, service);

        join!(
            async {
                s.lock().unwrap().feed_next(None);
            },
            async {
                server.await.unwrap();
            }
        );
    }

    #[tokio::test]
    async fn input_error() {
        let transport = FakeTransport::default();
        let service = FakeService;
        let s = Arc::clone(&transport.state);
        let server = Server::new(transport, service);

        join!(
            async {
                s.lock()
                    .unwrap()
                    .feed_next(Some(Err(io::ErrorKind::Other.into())));
            },
            async {
                assert!(server.await.is_err());
            }
        );
    }

    #[tokio::test]
    async fn initialize_channel() {
        let transport = FakeTransport::default();
        let service = FakeService;
        let s = Arc::clone(&transport.state);
        let server = Server::new(transport, service);

        join!(
            async {
                let request_message = RequestMessage {
                    channel_id: BROADCAST_CHANNEL_ID,
                    request: Request::Init {
                        nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                    },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o).unwrap(),
                    ResponseMessage {
                        channel_id: BROADCAST_CHANNEL_ID,
                        response: Response::Init {
                            nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                            new_channel_id: ChannelId(1),
                            ctaphid_protocol_version: 2,
                            major_device_version_number: 1,
                            minor_device_version_number: 2,
                            build_device_version_number: 3,
                            capabilities: CapabilityFlags::WINK,
                        },
                    }
                );

                s.lock().unwrap().feed_next(None);
            },
            async {
                server.await.unwrap();
            }
        );
    }

    #[tokio::test]
    async fn ping() {
        let transport = FakeTransport::default();
        let service = FakeService;
        let s = Arc::clone(&transport.state);
        let server = Server::new(transport, service);

        join!(
            async {
                // Initialize channel
                let request_message = RequestMessage {
                    channel_id: BROADCAST_CHANNEL_ID,
                    request: Request::Init {
                        nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                    },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o).unwrap(),
                    ResponseMessage {
                        channel_id: BROADCAST_CHANNEL_ID,
                        response: Response::Init {
                            nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                            new_channel_id: ChannelId(1),
                            ctaphid_protocol_version: 2,
                            major_device_version_number: 1,
                            minor_device_version_number: 2,
                            build_device_version_number: 3,
                            capabilities: CapabilityFlags::WINK,
                        },
                    }
                );

                // Ping
                let request_message = RequestMessage {
                    channel_id: ChannelId(1),
                    request: Request::Ping { data: vec![1] },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o).unwrap(),
                    ResponseMessage {
                        channel_id: ChannelId(1),
                        response: Response::Ping { data: vec![1] },
                    }
                );

                s.lock().unwrap().feed_next(None);
            },
            async {
                server.await.unwrap();
            }
        );
    }

    #[tokio::test]
    async fn wink() {
        let transport = FakeTransport::default();
        let service = FakeService;
        let s = Arc::clone(&transport.state);
        let server = Server::new(transport, service);

        join!(
            async {
                // Initialize channel
                let request_message = RequestMessage {
                    channel_id: BROADCAST_CHANNEL_ID,
                    request: Request::Init {
                        nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                    },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o).unwrap(),
                    ResponseMessage {
                        channel_id: BROADCAST_CHANNEL_ID,
                        response: Response::Init {
                            nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                            new_channel_id: ChannelId(1),
                            ctaphid_protocol_version: 2,
                            major_device_version_number: 1,
                            minor_device_version_number: 2,
                            build_device_version_number: 3,
                            capabilities: CapabilityFlags::WINK,
                        },
                    }
                );

                // Ping
                let request_message = RequestMessage {
                    channel_id: ChannelId(1),
                    request: Request::Wink,
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o).unwrap(),
                    ResponseMessage {
                        channel_id: ChannelId(1),
                        response: Response::Wink,
                    }
                );

                s.lock().unwrap().feed_next(None);
            },
            async {
                server.await.unwrap();
            }
        );
    }

    #[tokio::test]
    async fn msg() {
        let transport = FakeTransport::default();
        let service = FakeService;
        let s = Arc::clone(&transport.state);
        let server = Server::new(transport, service);

        join!(
            async {
                // Initialize channel
                let request_message = RequestMessage {
                    channel_id: BROADCAST_CHANNEL_ID,
                    request: Request::Init {
                        nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                    },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o).unwrap(),
                    ResponseMessage {
                        channel_id: BROADCAST_CHANNEL_ID,
                        response: Response::Init {
                            nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                            new_channel_id: ChannelId(1),
                            ctaphid_protocol_version: 2,
                            major_device_version_number: 1,
                            minor_device_version_number: 2,
                            build_device_version_number: 3,
                            capabilities: CapabilityFlags::WINK,
                        },
                    }
                );

                // Msg
                let request_message = RequestMessage {
                    channel_id: ChannelId(1),
                    request: Request::Msg { data: vec![0] },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o).unwrap(),
                    ResponseMessage {
                        channel_id: ChannelId(1),
                        response: Response::Msg {
                            data: vec!['m' as u8, 's' as u8, 'g' as u8]
                        },
                    }
                );

                s.lock().unwrap().feed_next(None);
            },
            async {
                server.await.unwrap();
            }
        );
    }

    #[tokio::test]
    async fn msg_multiple() {
        let transport = FakeTransport::default();
        let service = FakeService;
        let s = Arc::clone(&transport.state);
        let server = Server::new(transport, service);

        join!(
            async {
                // Initialize channel
                let request_message = RequestMessage {
                    channel_id: BROADCAST_CHANNEL_ID,
                    request: Request::Init {
                        nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                    },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o).unwrap(),
                    ResponseMessage {
                        channel_id: BROADCAST_CHANNEL_ID,
                        response: Response::Init {
                            nonce: [0, 1, 2, 3, 4, 5, 6, 7],
                            new_channel_id: ChannelId(1),
                            ctaphid_protocol_version: 2,
                            major_device_version_number: 1,
                            minor_device_version_number: 2,
                            build_device_version_number: 3,
                            capabilities: CapabilityFlags::WINK,
                        },
                    }
                );

                // Msg (multiple)
                let request_message = RequestMessage {
                    channel_id: ChannelId(1),
                    request: Request::Msg { data: vec![0] },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                let request_message = RequestMessage {
                    channel_id: ChannelId(1),
                    request: Request::Msg { data: vec![0] },
                };

                for packet in request_message.to_packets() {
                    s.lock().unwrap().feed_next(Some(Ok(packet)));
                }

                sleep(Duration::from_millis(100)).await;

                let o = std::mem::replace(&mut s.lock().unwrap().output, vec![]);

                assert_eq!(
                    ResponseMessage::decode(&o[0..1]).unwrap(),
                    ResponseMessage {
                        channel_id: ChannelId(1),
                        response: Response::Msg {
                            data: vec!['m' as u8, 's' as u8, 'g' as u8]
                        },
                    }
                );

                assert_eq!(
                    ResponseMessage::decode(&o[1..2]).unwrap(),
                    ResponseMessage {
                        channel_id: ChannelId(1),
                        response: Response::Msg {
                            data: vec!['m' as u8, 's' as u8, 'g' as u8]
                        },
                    }
                );

                s.lock().unwrap().feed_next(None);
            },
            async {
                server.await.unwrap();
            }
        );
    }
}
