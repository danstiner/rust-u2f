use crate::api::CtapHidApi;
use crate::channel::ChannelId;
use crate::channel::Channels;
use crate::channel::BROADCAST_CHANNEL_ID;
use crate::message::*;
use crate::packet::*;
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
use tracing::{debug, info, trace};

#[pin_project]
pub struct Protocol<S, E> {
    channels: HashMap<ChannelId, ChannelState<E>>,
    channel_allocator: Channels,
    service: S,
    output: VecDeque<Packet>,
    output_waker: Option<Waker>,
}

impl<Api, Error> Protocol<Api, Error>
where
    Api: CtapHidApi<Error = Error>,
    Error: From<Api::Error> + From<io::Error> + 'static,
{
    pub fn new(service: Api) -> Protocol<Api, Error> {
        Protocol {
            channels: HashMap::new(),
            channel_allocator: Channels::new(),
            service,
            output: VecDeque::new(),
            output_waker: None,
        }
    }
}

impl<S, E> Sink<Packet> for Protocol<S, E>
where
    S: CtapHidApi + Clone + 'static,
    E: From<S::Error> + 'static,
{
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, packet: Packet) -> Result<(), Self::Error> {
        let this = self.project();

        if packet.channel_id() == BROADCAST_CHANNEL_ID {
            // Only initialization messages are valid on the broadcast channel
            return match RequestMessage::decode(&[packet]) {
                Ok(RequestMessage {
                    channel_id,
                    request,
                }) => match request {
                    Request::Init { nonce } => {
                        let version = this.service.version().unwrap_or_else(|_| todo!());

                        let new_channel_id = this
                            .channel_allocator
                            .allocate()
                            .expect("Failed to allocate new channel");

                        this.channels.insert(new_channel_id, ChannelState::Ready);

                        this.output.append(
                            &mut ResponseMessage {
                                channel_id,
                                response: Response::Init {
                                    nonce,
                                    new_channel_id,
                                    ctaphid_protocol_version: CTAPHID_PROTOCOL_VERSION,
                                    major_device_version_number: version.major,
                                    minor_device_version_number: version.minor,
                                    build_device_version_number: version.build,
                                    capabilities: version.capabilities,
                                },
                            }
                            .to_packets(),
                        );
                        this.output_waker.take().map(|waker| waker.wake());
                        Ok(())
                    }
                    _ => Err(todo!("Bad packet for broadcast channel")),
                },
                Err(..) => Err(todo!("Bad init packet")),
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
                    if data.len() == payload_len.into() {
                        match Request::decode(command, &data) {
                            Ok(request) => match request {
                                Request::Ping { data } => {
                                    this.output.append(
                                        &mut ResponseMessage {
                                            channel_id,
                                            response: Response::Ping { data },
                                        }
                                        .to_packets(),
                                    );
                                    this.output_waker.take().map(|waker| waker.wake());
                                }
                                Request::Msg { data } => {
                                    let service = this.service.clone();
                                    *state = ChannelState::Processing {
                                        future: Box::pin(async move {
                                            Ok(Response::Msg {
                                                data: service.msg(&data).await?,
                                            })
                                        }),
                                    };
                                }
                                Request::Init { nonce } => {
                                    return Err(todo!(
                                        "init messages only valid on broadcast channel"
                                    ));
                                }
                                Request::Cbor { data } => {
                                    let service = this.service.clone();
                                    *state = ChannelState::Processing {
                                        future: Box::pin(async move {
                                            Ok(Response::Cbor {
                                                data: service.cbor(&data).await?,
                                            })
                                        }),
                                    };
                                }
                                Request::Cancel => todo!(),
                                Request::Lock { lock_time } => todo!(),
                                Request::Wink => {
                                    let service = this.service.clone();
                                    *state = ChannelState::Processing {
                                        future: Box::pin(async move {
                                            service.wink().await?;
                                            Ok(Response::Wink)
                                        }),
                                    };
                                }
                            },
                            Err(err) => todo!("Unhandled error {:?}", err),
                        }
                    } else {
                        *state = ChannelState::Receiving {
                            command,
                            payload: data,
                            payload_len,
                            next_sequence_number: 0,
                        };
                    }

                    Ok(())
                }
                Packet::Continuation { .. } => Err(todo!("Unexpected Continuation packet")),
            },
            ChannelState::Receiving {
                command,
                ref mut payload,
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

                    payload.append(&mut data);

                    if payload.len() == (*payload_len).into() {
                        match Request::decode(*command, &payload) {
                            Ok(request) => match request {
                                Request::Ping { data } => {
                                    this.output.append(
                                        &mut ResponseMessage {
                                            channel_id,
                                            response: Response::Ping { data },
                                        }
                                        .to_packets(),
                                    );
                                    this.output_waker.take().map(|waker| waker.wake());
                                }
                                Request::Msg { data } => {
                                    let service = this.service.clone();
                                    *state = ChannelState::Processing {
                                        future: Box::pin(async move {
                                            Ok(Response::Msg {
                                                data: service.msg(&data).await?,
                                            })
                                        }),
                                    };
                                }
                                Request::Init { nonce } => {
                                    return Err(todo!(
                                        "init messages only valid on broadcast channel"
                                    ));
                                }
                                Request::Cbor { data } => {
                                    let service = this.service.clone();
                                    *state = ChannelState::Processing {
                                        future: Box::pin(async move {
                                            Ok(Response::Cbor {
                                                data: service.cbor(&data).await?,
                                            })
                                        }),
                                    };
                                }
                                Request::Cancel => todo!(),
                                Request::Lock { lock_time } => todo!(),
                                Request::Wink => {
                                    let service = this.service.clone();
                                    *state = ChannelState::Processing {
                                        future: Box::pin(async move {
                                            service.wink().await?;
                                            Ok(Response::Wink)
                                        }),
                                    };
                                }
                            },
                            Err(err) => todo!("Unhandled error {:?}", err),
                        }
                    }

                    Ok(())
                }
                Packet::Initialization { .. } => Err(todo!("Unexpected Initialization packet")),
            },
            ChannelState::Processing { .. } => Err(todo!("Channel busy")),
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

impl<S, E> Stream for Protocol<S, E>
where
    E: fmt::Debug,
{
    type Item = Packet;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        if this.output.is_empty() {
            // Try to produce some output by polling all channels
            for (channel_id, state) in this.channels.iter_mut() {
                match state {
                    ChannelState::Processing { future } => match future.as_mut().poll(cx) {
                        Poll::Ready(Ok(response)) => {
                            this.output.append(
                                &mut ResponseMessage {
                                    channel_id: *channel_id,
                                    response,
                                }
                                .to_packets(),
                            );
                            *state = ChannelState::Ready;
                        }
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            info!("Error processing request: {:?}", e);
                            this.output.append(
                                &mut ResponseMessage {
                                    channel_id: *channel_id,
                                    response: Response::Error {
                                        code: ErrorCode::Other,
                                    },
                                }
                                .to_packets(),
                            );
                            *state = ChannelState::Ready;
                        }
                    },
                    ChannelState::Ready { .. } => {}
                    ChannelState::Receiving { .. } => {}
                }
            }
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

enum ChannelState<Error> {
    Ready,
    Receiving {
        command: CommandType,
        payload: Vec<u8>,
        payload_len: u16,
        next_sequence_number: u8,
    },
    Processing {
        future: Pin<Box<dyn Future<Output = Result<Response, Error>>>>,
    },
}

impl<E> Default for ChannelState<E> {
    fn default() -> Self {
        ChannelState::Ready
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use futures::{SinkExt, StreamExt};

    use crate::{api::VersionInfo, channel::BROADCAST_CHANNEL_ID};

    use super::*;

    struct FakeApi;

    #[async_trait]
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
        async fn msg(&self, _msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(vec!['m' as u8, 's' as u8, 'g' as u8])
        }
        async fn cbor(&self, _cbor: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(vec!['c' as u8, 'b' as u8, 'o' as u8, 'r' as u8])
        }
    }

    async fn init_channel(protocol: &mut Protocol<Arc<FakeApi>, io::Error>) -> ChannelId {
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

    async fn send_request(
        channel_id: ChannelId,
        request: Request,
        protocol: &mut Protocol<Arc<FakeApi>, io::Error>,
    ) {
        let request_message = RequestMessage {
            channel_id,
            request,
        };

        for packet in request_message.to_packets() {
            protocol.send(packet).await.unwrap();
        }
    }

    async fn next_response(
        expected_channel_id: ChannelId,
        protocol: &mut Protocol<Arc<FakeApi>, io::Error>,
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
