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
        trace!("U2fHidServer::poll");
        let this = &mut *self;
        loop {
            // First flush any buffered packets
            if let Some(mut buffer) = this.send_buffer.take() {
                trace!(
                    "U2fHidServer::poll: Sending {} buffered packets",
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
                            "U2fHidServer::poll: Start send packet, remaining: {}",
                            buffer.len()
                        );
                        this.send_buffer = Some(buffer);
                        Pin::new(&mut this.transport).start_send(packet)?;
                        continue;
                    }
                    None => {
                        // All packets in the buffer have been sent, flush before clearing entirely
                        trace!("U2fHidServer::poll: Flushing");
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

#[cfg(test)]
mod tests {
    use futures::join;

    use crate::{ChannelId, Command, BROADCAST_CHANNEL_ID};

    use self::mock::stream::{Builder, Handle, Mock};

    use super::*;

    mod mock {
        pub mod stream {
            use std::{
                collections::VecDeque,
                fmt,
                pin::Pin,
                task::{Context, Poll},
            };

            use tokio::sync::mpsc;

            use futures::{Sink, Stream};

            /// A stream (and sink) object that follows a predefined script.
            ///
            /// This value is created by `Builder` and implements `Stream` + `Sink`.
            /// It follows the scenario described by the builder and panics otherwise.
            #[derive(Debug)]
            pub struct Mock<N, S, E> {
                inner: Inner<N, S, E>,
            }

            #[derive(Debug)]
            pub struct Handle<N, S, E> {
                tx: mpsc::UnboundedSender<Action<N, S, E>>,
            }

            #[derive(Debug, Clone)]
            pub struct Builder<N, S, E> {
                actions: VecDeque<Action<N, S, E>>,
            }

            #[derive(Debug, Clone)]
            enum Action<N, S, E> {
                Next(N),
                Send(S),
                SendError(E),
            }

            #[derive(Debug)]
            struct Inner<N, S, E> {
                actions: VecDeque<Action<N, S, E>>,
                // rx: UnboundedReceiverStream<Action>,
            }

            impl<N, S, E> Builder<N, S, E> {
                /// Return a new, empty `Builder`.
                pub fn new() -> Self {
                    Self::default()
                }

                pub fn next(&mut self, item: N) -> &mut Self {
                    self.actions.push_back(Action::Next(item));
                    self
                }

                pub fn send(&mut self, item: S) -> &mut Self {
                    self.actions.push_back(Action::Send(item));
                    self
                }

                pub fn send_error(&mut self, error: E) -> &mut Self {
                    self.actions.push_back(Action::SendError(error));
                    self
                }

                pub fn build(self) -> Mock<N, S, E> {
                    let (mock, _) = self.build_with_handle();
                    mock
                }

                pub fn build_with_handle(self) -> (Mock<N, S, E>, Handle<N, S, E>) {
                    let (inner, handle) = Inner::new(self.actions);

                    let mock = Mock { inner };

                    (mock, handle)
                }
            }

            impl<N, S, E> Handle<N, S, E> {
                pub fn next(&mut self, item: N) {
                    todo!()
                }

                pub fn send(&mut self, item: S) {
                    todo!()
                }

                pub async fn wait_for_send<T>(&mut self) -> S {
                    todo!()
                }

                pub fn send_error(&mut self, error: E) {
                    todo!()
                }
            }

            impl<N, S, E> Inner<N, S, E> {
                pub fn new(actions: VecDeque<Action<N, S, E>>) -> (Self, Handle<N, S, E>) {
                    let (tx, rx) = mpsc::unbounded_channel();

                    let inner = Self { actions };
                    let handle = Handle { tx };

                    (inner, handle)
                }
            }

            impl<N, S, E> Default for Builder<N, S, E> {
                fn default() -> Self {
                    Self {
                        actions: Default::default(),
                    }
                }
            }

            impl<N, S, E> Stream for Mock<N, S, E>
            where
                N: Unpin,
                S: Unpin,
                E: Unpin,
            {
                type Item = N;

                fn poll_next(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<Option<Self::Item>> {
                    match self.inner.pop_action() {
                        Some(Action::Next(item)) => Poll::Ready(Some(item)),
                        Some(_) => panic!("unexpected poll_next"),
                        None => Poll::Ready(None),
                    }
                }
            }

            impl<N, S, E> Sink<S> for Mock<N, S, E>
            where
                N: Unpin,
                S: Unpin + PartialEq + fmt::Debug,
                E: Unpin,
            {
                type Error = E;

                fn poll_ready(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<Result<(), Self::Error>> {
                    Poll::Ready(Ok(()))
                }

                fn start_send(mut self: Pin<&mut Self>, item: S) -> Result<(), Self::Error> {
                    match self.inner.pop_action() {
                        Some(Action::Send(expected)) => {
                            assert_eq!(item, expected);
                            Ok(())
                        }
                        _ => panic!("unexpected start_send"),
                    }
                }

                fn poll_flush(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<Result<(), Self::Error>> {
                    Poll::Ready(Ok(()))
                }

                fn poll_close(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<Result<(), Self::Error>> {
                    Poll::Ready(Ok(()))
                }
            }

            impl<N, S, E> Inner<N, S, E> {
                fn pop_action(&mut self) -> Option<Action<N, S, E>> {
                    self.actions.pop_front()
                }
            }

            /// Ensures that Mock isn't dropped with data "inside".
            impl<N, S, E> Drop for Mock<N, S, E> {
                fn drop(&mut self) {
                    // Avoid double panicking, since makes debugging much harder.
                    if std::thread::panicking() {
                        return;
                    }

                    self.inner.actions.iter().for_each(|a| match a {
                        Action::Next(_) => {
                            panic!("There are still item(s) left to read from the stream.")
                        }
                        Action::Send(_) => {
                            panic!("There are still item(s) expected to be sent for the sink.")
                        }
                        _ => (),
                    })
                }
            }
        }
    }

    struct FakeU2FService;

    impl Service<u2f_core::Request> for FakeU2FService {
        type Response = u2f_core::Response;
        type Error = io::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u2f_core::Request) -> Self::Future {
            panic!("Fake service, not implemented")
        }
    }

    async fn init_channel<S>(transport: &Handle<Packet, Packet, io::Error>) -> ChannelId {
        let request_nonce: [u8; 8] = rand::random();
        let data = request_nonce.to_vec();

        transport.next(Packet::Initialization {
            channel_id: BROADCAST_CHANNEL_ID,
            command: Command::Init,
            data: data,
            payload_len: data.len() as u16,
        });

        let packet = transport.wait_for_send().await;

        todo!()

        // match packet {
            
        // }

        // match  {
        //     Response {
        //         channel_id: response_channel_id,
        //         message:
        //             ResponseMessage::Init {
        //                 new_channel_id,
        //                 nonce,
        //                 ..
        //             },
        //     } => {
        //         assert_eq!(response_channel_id, BROADCAST_CHANNEL_ID);
        //         assert_eq!(request_nonce, nonce);
        //         assert!(state_machine.channels.is_valid(new_channel_id));
        //         new_channel_id
        //     }
        //     _ => panic!(),
        // }
    }

    #[tokio::test]
    async fn init() {
        let hid_transport: Mock<Result<Packet, io::Error>, Packet, io::Error> =
            Builder::new().build();
        let u2f_service = FakeU2FService;
        let server: Result<(), io::Error> = U2fHidServer::new(hid_transport, u2f_service).await;
        server.unwrap();
        panic!("test");
    }

    
    #[tokio::test]
    async fn ping() {
        let ping_data: [u8; 8] = rand::random();
        let packet_data = ping_data.to_vec();
        let packet_data_len = packet_data.len() as u16;

        let (hid_transport, handle) = Builder::new().build_with_handle();
        let u2f_service = FakeU2FService;
        let server = U2fHidServer::new(hid_transport, u2f_service);

        let transport_simulation = async {
            let channel_id = init_channel(handle);
            handle.next(Ok(Packet::Initialization {
                channel_id: channel_id,
                command: Command::Ping,
                data: packet_data,
                payload_len: packet_data_len,
            }));
            handle.send();
        };

        join!(async { server.await.unwrap() }, transport_simulation);
    }

    //     match res {
    //         Some(Response {
    //             channel_id: response_channel_id,
    //             message:
    //                 ResponseMessage::Pong {
    //                     data: response_data,
    //                 },
    //         }) => {
    //             assert_eq!(response_channel_id, channel_id);
    //             assert_eq!(response_data[..], ping_data);
    //         }
    //         _ => panic!(),
    //     };
    // }
}
