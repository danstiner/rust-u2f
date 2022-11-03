use crate::api::CtapHidApi;
use crate::channel::ChannelId;
use crate::channel::Channels;
use crate::channel::BROADCAST_CHANNEL_ID;
use crate::packet::*;
use crate::request::Request;
use crate::request::RequestMessage;
use crate::response::Response;
use crate::response::ResponseMessage;
use crate::CommandType;
use crate::ErrorCode;
use crate::CTAPHID_PROTOCOL_VERSION;
use futures::Future;
use futures::Sink;
use futures::Stream;
use pin_project::pin_project;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use tracing::info;
use tracing::trace;

#[pin_project]
pub struct Protocol<'a, Api, Error> {
    service_state: ServiceState<'a, Api, Error>,
    channels: HashMap<ChannelId, ChannelState>,
    channel_allocator: Channels,
    output: VecDeque<Packet>,
    output_waker: Option<Waker>,
}

enum ServiceState<'a, Service, Error> {
    Ready(Service),
    Processing {
        channel_id: ChannelId,
        future: Pin<Box<dyn Future<Output = (Service, Result<Response, Error>)> + 'a>>,
    },
    /// Invalid state, used if a panic occurs while transitioning between states
    Invalid,
}

impl<'a, Service, Error> ServiceState<'a, Service, Error>
where
    Error: fmt::Debug,
{
    fn process_request(
        &mut self,
        channel_id: ChannelId,
        command: CommandType,
        data: &[u8],
        output: &mut VecDeque<Packet>,
        output_waker: &mut Option<Waker>,
    ) -> Result<(), Error>
    where
        Service: CtapHidApi<Error = Error> + 'a,
        Error: From<Service::Error> + 'static,
    {
        let request = match Request::decode(command, data) {
            Ok(request) => request,
            Err(_err) => todo!("return (self, Err(err.into()))"),
        };

        let this = std::mem::replace(self, ServiceState::Invalid);

        let (result, new_state) =
            this.process_request_move(channel_id, request, output, output_waker);

        *self = new_state;

        result
    }

    fn process_request_move(
        self,
        channel_id: ChannelId,
        request: Request,
        output: &mut VecDeque<Packet>,
        output_waker: &mut Option<Waker>,
    ) -> (Result<(), Error>, Self)
    where
        Service: CtapHidApi<Error = Error> + 'a,
        Error: From<Service::Error> + 'static,
    {
        let service = match self {
            ServiceState::Ready(service) => service,
            _ => todo!("return error, bad state"),
        };

        let next_state = match request {
            Request::Ping { data } => {
                output.append(
                    &mut ResponseMessage {
                        channel_id,
                        response: Response::Ping { data },
                    }
                    .to_packets(),
                );
                if let Some(waker) = output_waker.take() {
                    waker.wake()
                }
                ServiceState::Ready(service)
            }
            Request::Msg { data } => ServiceState::Processing {
                channel_id,
                future: Box::pin(async move {
                    match service.msg(data).await {
                        Ok(data) => (service, Ok(Response::Msg { data })),
                        Err(err) => (service, Err(err)),
                    }
                }),
            },
            Request::Init { nonce: _ } => {
                todo!("Err: init messages only valid on broadcast channel");
            }
            Request::Cbor { data } => ServiceState::Processing {
                channel_id,
                future: Box::pin(async move {
                    match service.cbor(data).await {
                        Ok(data) => (service, Ok(Response::Cbor { data })),
                        Err(err) => (service, Err(err)),
                    }
                }),
            },
            Request::Cancel => todo!(),
            Request::Lock { lock_time: _ } => todo!(),
            Request::Wink => ServiceState::Processing {
                channel_id,
                future: Box::pin(async move {
                    match service.wink().await {
                        Ok(()) => (service, Ok(Response::Wink)),
                        Err(err) => (service, Err(err)),
                    }
                }),
            },
        };

        (Ok(()), next_state)
    }

    fn try_produce_output(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut VecDeque<Packet>,
    ) -> Poll<()> {
        let this = std::mem::replace(self, ServiceState::Invalid);
        let (result, new_state) = this.try_produce_output_move(cx, output);
        *self = new_state;
        result
    }

    fn try_produce_output_move(
        self,
        cx: &mut Context<'_>,
        output: &mut VecDeque<Packet>,
    ) -> (Poll<()>, Self) {
        match self {
            ServiceState::Processing {
                channel_id,
                mut future,
            } => match future.as_mut().poll(cx) {
                Poll::Ready((service, Ok(response))) => {
                    output.append(
                        &mut ResponseMessage {
                            channel_id,
                            response,
                        }
                        .to_packets(),
                    );
                    (Poll::Ready(()), ServiceState::Ready(service))
                }
                Poll::Pending => (
                    Poll::Pending,
                    ServiceState::Processing { channel_id, future },
                ),
                Poll::Ready((service, Err(e))) => {
                    info!("Error processing request: {:?}", e);
                    output.append(
                        &mut ResponseMessage {
                            channel_id,
                            response: Response::Error {
                                code: ErrorCode::Other,
                            },
                        }
                        .to_packets(),
                    );
                    (Poll::Ready(()), ServiceState::Ready(service))
                }
            },
            ServiceState::Ready(service) => (Poll::Ready(()), ServiceState::Ready(service)),
            _ => unreachable!(),
        }
    }
}

enum ChannelState {
    Ready,
    Receiving {
        command: CommandType,
        payload: Vec<u8>,
        payload_len: u16,
        next_sequence_number: u8,
    },
}

impl<'a, Api, Error> Protocol<'a, Api, Error>
where
    Api: CtapHidApi<Error = Error> + 'a,
    Error: From<Api::Error> + From<io::Error> + 'static,
{
    pub fn new(service: Api) -> Self {
        Protocol {
            service_state: ServiceState::Ready(service),
            channels: HashMap::new(),
            channel_allocator: Channels::new(),
            output: VecDeque::new(),
            output_waker: None,
        }
    }
}

impl<'a, Api, Error> Sink<Packet> for Protocol<'a, Api, Error>
where
    Api: CtapHidApi<Error = Error> + 'a,
    Error: From<Api::Error> + From<io::Error> + fmt::Debug + 'static,
{
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        match this.service_state {
            ServiceState::Ready(_) => Poll::Ready(Ok(())),
            ServiceState::Processing { .. } => Poll::Pending, // todo register waker
            ServiceState::Invalid => unreachable!(),
        }
    }

    fn start_send(self: Pin<&mut Self>, packet: Packet) -> Result<(), Self::Error> {
        let this = self.project();

        trace!("start_send packet:{:?}", packet);

        if packet.channel_id() == BROADCAST_CHANNEL_ID {
            // Only initialization messages are valid on the broadcast channel
            return match RequestMessage::decode(&[packet]) {
                Ok(RequestMessage {
                    channel_id,
                    request,
                }) => match request {
                    Request::Init { nonce } => {
                        let service = match this.service_state {
                            ServiceState::Ready(service) => service,
                            ServiceState::Processing { .. } => todo!("Error, not ready"),
                            ServiceState::Invalid => unreachable!(),
                        };
                        let version = service.version().unwrap_or_else(|_| todo!());

                        let new_channel_id = this
                            .channel_allocator
                            .allocate()
                            .expect("Failed to allocate new channel");

                        this.channels.insert(new_channel_id, ChannelState::Ready);

                        let response = Response::Init {
                            nonce,
                            new_channel_id,
                            ctaphid_protocol_version: CTAPHID_PROTOCOL_VERSION,
                            major_device_version_number: version.major,
                            minor_device_version_number: version.minor,
                            build_device_version_number: version.build,
                            capabilities: version.capabilities,
                        };

                        trace!(
                            "start_send on broadcast_channel request:{:?} response:{:?}",
                            request,
                            response
                        );

                        this.output.append(
                            &mut ResponseMessage {
                                channel_id,
                                response,
                            }
                            .to_packets(),
                        );
                        if let Some(waker) = this.output_waker.take() {
                            waker.wake()
                        }
                        Ok(())
                    }
                    _ => todo!("Err: Bad packet for broadcast channel"),
                },
                Err(..) => todo!("Err: Bad init packet"),
            };
        }

        let state = this.channels.get_mut(&packet.channel_id()).unwrap();

        match state {
            ChannelState::Ready => match packet {
                Packet::Initialization {
                    channel_id,
                    command,
                    data,
                    payload_len,
                } => {
                    if data.len() >= payload_len.into() {
                        this.service_state.process_request(
                            channel_id,
                            command,
                            &data[0..payload_len.into()],
                            this.output,
                            this.output_waker,
                        )
                    } else {
                        *state = ChannelState::Receiving {
                            command,
                            payload: data,
                            payload_len,
                            next_sequence_number: 0,
                        };

                        Ok(())
                    }
                }
                Packet::Continuation { .. } => todo!("Err: Unexpected Continuation packet"),
            },
            ChannelState::Receiving {
                command,
                payload: ref mut payload_buffer,
                payload_len,
                ref mut next_sequence_number,
            } => match packet {
                Packet::Continuation {
                    channel_id,
                    sequence_number,
                    mut data,
                } => {
                    assert_eq!(sequence_number, *next_sequence_number);
                    *next_sequence_number += 1;

                    payload_buffer.append(&mut data);

                    if payload_buffer.len() >= (*payload_len).into() {
                        this.service_state.process_request(
                            channel_id,
                            *command,
                            &(*payload_buffer)[0..(*payload_len).into()],
                            this.output,
                            this.output_waker,
                        )?;
                        *state = ChannelState::Ready;
                    }
                    Ok(())
                }
                Packet::Initialization { .. } => todo!("Err: Unexpected Initialization packet"),
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // TODO
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // TODO
        Poll::Ready(Ok(()))
    }
}

impl<'a, S, E> Stream for Protocol<'a, S, E>
where
    E: fmt::Debug,
{
    type Item = Packet;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        if this.output.is_empty() {
            match this.service_state.try_produce_output(cx, this.output) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            };
        }

        if let Some(packet) = this.output.pop_front() {
            // Return the next output packet
            Poll::Ready(Some(packet))
        } else {
            // No output currently, wait until there is some
            this.output_waker.replace(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use futures::{SinkExt, StreamExt};

    use crate::{api::VersionInfo, channel::BROADCAST_CHANNEL_ID, CapabilityFlags, CommandType};

    use super::*;

    struct FakeApi;

    #[async_trait(?Send)]
    impl CtapHidApi for FakeApi {
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

    async fn init_channel<'a>(protocol: &mut Protocol<'a, Arc<FakeApi>, io::Error>) -> ChannelId {
        send_request(
            BROADCAST_CHANNEL_ID,
            Request::Init {
                nonce: [0, 1, 2, 3, 4, 5, 6, 7],
            },
            protocol,
        )
        .await;

        assert_eq!(
            protocol.next().await,
            Some(Packet::Initialization {
                channel_id: BROADCAST_CHANNEL_ID,
                command: CommandType::Init,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 1, 2, 1, 2, 3, 1],
                payload_len: 17,
            })
        );

        ChannelId(1)
    }

    async fn send_request<'a>(
        channel_id: ChannelId,
        request: Request,
        protocol: &mut Protocol<'a, Arc<FakeApi>, io::Error>,
    ) {
        let request_message = RequestMessage {
            channel_id,
            request,
        };

        for packet in request_message.to_packets() {
            protocol.send(packet).await.unwrap();
        }
    }

    async fn next_response<'a>(
        expected_channel_id: ChannelId,
        protocol: &mut Protocol<'a, Arc<FakeApi>, io::Error>,
    ) -> Response {
        let (command, mut payload, payload_len) = match protocol.next().await {
            Some(Packet::Initialization {
                channel_id,
                command,
                data,
                payload_len,
            }) => {
                assert_eq!(channel_id, expected_channel_id);
                (command, data, payload_len)
            }
            _ => todo!("Error, unexpected packet"),
        };

        let mut expected_sequence_number = 0u8;
        while payload.len() < payload_len.into() {
            match protocol.next().await {
                Some(Packet::Continuation {
                    channel_id,
                    sequence_number,
                    mut data,
                }) => {
                    assert_eq!(channel_id, expected_channel_id);
                    assert_eq!(sequence_number, expected_sequence_number);

                    expected_sequence_number += 1;
                    payload.append(&mut data);
                }
                _ => todo!("Error, unexpected packet"),
            }
        }

        assert_eq!(payload.len(), payload_len.into());
        Response::decode(command, &payload).unwrap()
    }

    #[tokio::test]
    async fn init() {
        let mut protocol = Protocol::new(Arc::new(FakeApi));
        let init_request = RequestMessage {
            channel_id: BROADCAST_CHANNEL_ID,
            request: Request::Init {
                nonce: [0, 1, 2, 3, 4, 5, 6, 7],
            },
        };

        for packet in init_request.to_packets() {
            protocol.send(packet).await.unwrap();
        }

        assert_eq!(
            protocol.next().await,
            Some(Packet::Initialization {
                channel_id: BROADCAST_CHANNEL_ID,
                command: CommandType::Init,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 1, 2, 1, 2, 3, 1],
                payload_len: 17,
            })
        );
    }

    #[tokio::test]
    async fn ping() {
        let mut protocol = Protocol::new(Arc::new(FakeApi));

        let channel_id = init_channel(&mut protocol).await;

        send_request(
            channel_id,
            Request::Ping {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7],
            },
            &mut protocol,
        )
        .await;

        assert_eq!(
            next_response(channel_id, &mut protocol).await,
            Response::Ping {
                data: vec![0, 1, 2, 3, 4, 5, 6, 7]
            }
        );
    }

    #[tokio::test]
    async fn wink() {
        let mut protocol = Protocol::new(Arc::new(FakeApi));

        let channel_id = init_channel(&mut protocol).await;

        send_request(channel_id, Request::Wink, &mut protocol).await;

        assert_eq!(
            next_response(channel_id, &mut protocol).await,
            Response::Wink
        );
    }

    #[tokio::test]
    async fn msg() {
        let mut protocol = Protocol::new(Arc::new(FakeApi));

        let channel_id = init_channel(&mut protocol).await;

        send_request(
            channel_id,
            Request::Msg {
                data: (0u8..100).collect(),
            },
            &mut protocol,
        )
        .await;

        assert_eq!(
            next_response(channel_id, &mut protocol).await,
            Response::Msg {
                data: vec!['m' as u8, 's' as u8, 'g' as u8],
            }
        );
    }

    #[tokio::test]
    async fn cbor() {
        let mut protocol = Protocol::new(Arc::new(FakeApi));

        let channel_id = init_channel(&mut protocol).await;

        send_request(
            channel_id,
            Request::Cbor {
                data: (0u8..100).collect(),
            },
            &mut protocol,
        )
        .await;

        assert_eq!(
            next_response(channel_id, &mut protocol).await,
            Response::Cbor {
                data: vec!['c' as u8, 'b' as u8, 'o' as u8, 'r' as u8],
            }
        );
    }

    // TODO: test error handling
    // TODO: test channel management and concurrent sends
}
