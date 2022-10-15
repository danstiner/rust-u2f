use crate::api::CtapHidApi;
use crate::channel::ChannelId;
use crate::channel::Channels;
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
    channel_state: HashMap<ChannelId, ChannelState<E>>,
    channels: Channels,
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
            channel_state: HashMap::new(),
            channels: Channels::new(),
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
        let state = this.channel_state.entry(packet.channel_id()).or_default();
        match state {
            ChannelState::Receiving { packets } => {
                packets.push(packet);
                match RequestMessage::decode(packets) {
                    Ok(message) => {
                        match message.request {
                            Request::Ping { data } => {
                                this.output.append(
                                    &mut ResponseMessage {
                                        channel_id: message.channel_id,
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
                                let version = this.service.version().unwrap_or_else(|_| todo!());

                                let new_channel_id = ChannelId(1); // TODO
                                                                   // self
                                                                   //     .channels
                                                                   //     .allocate()
                                                                   //     .expect("Failed to allocate new channel");

                                this.output.append(
                                    &mut ResponseMessage {
                                        channel_id: message.channel_id,
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
                        }
                    }
                    Err(err) => todo!("Unhandled error {:?}", err),
                }
                // TODO transition to processing state?
                Ok(())
            }
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
            // Poll any currently processing channels
            for (channel_id, state) in this.channel_state.iter_mut() {
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
                            *state = ChannelState::Receiving {
                                packets: Vec::new(),
                            };
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
                            *state = ChannelState::Receiving {
                                packets: Vec::new(),
                            };
                        }
                    },
                    ChannelState::Receiving { .. } => {}
                }
            }
        }

        if let Some(packet) = this.output.pop_front() {
            Poll::Ready(Some(packet))
        } else {
            this.output_waker.replace(cx.waker().clone());
            Poll::Pending
        }
    }
}

enum ChannelState<Error> {
    Receiving {
        packets: Vec<Packet>,
    },
    Processing {
        future: Pin<Box<dyn Future<Output = Result<Response, Error>>>>,
    },
}

impl<E> Default for ChannelState<E> {
    fn default() -> Self {
        ChannelState::Receiving {
            packets: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use futures::{SinkExt, StreamExt};

    use crate::{api::VersionInfo, channel::BROADCAST_CHANNEL_ID};

    use super::*;

    struct MockApi;

    #[async_trait]
    impl CtapHidApi for MockApi {
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

    #[tokio::test]
    async fn init() {
        let mut protocol = Protocol::new(Arc::new(MockApi));

        protocol
            .send(Packet::Initialization {
                channel_id: BROADCAST_CHANNEL_ID,
                command: CommandType::Init,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7],
                payload_len: 8,
            })
            .await
            .unwrap();

        assert_eq!(
            protocol.next().await.unwrap(),
            Packet::Initialization {
                channel_id: BROADCAST_CHANNEL_ID,
                command: CommandType::Init,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 1, 2, 1, 2, 3, 1],
                payload_len: 17,
            }
        );
    }

    #[tokio::test]
    async fn ping() {
        let mut protocol = Protocol::new(Arc::new(MockApi));

        protocol
            .send(Packet::Initialization {
                channel_id: BROADCAST_CHANNEL_ID,
                command: CommandType::Ping,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7],
                payload_len: 8,
            })
            .await
            .unwrap();

        assert_eq!(
            protocol.next().await.unwrap(),
            Packet::Initialization {
                channel_id: BROADCAST_CHANNEL_ID,
                command: CommandType::Ping,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7],
                payload_len: 8,
            }
        );
    }

    #[tokio::test]
    async fn wink() {
        let mut protocol = Protocol::new(Arc::new(MockApi));

        protocol
            .send(Packet::Initialization {
                channel_id: ChannelId(1),
                command: CommandType::Wink,
                data: vec![],
                payload_len: 0,
            })
            .await
            .unwrap();

        assert_eq!(
            protocol.next().await.unwrap(),
            Packet::Initialization {
                channel_id: ChannelId(1),
                command: CommandType::Wink,
                data: vec![],
                payload_len: 0,
            }
        );
    }

    #[tokio::test]
    async fn msg() {
        let mut protocol = Protocol::new(Arc::new(MockApi));

        protocol
            .send(Packet::Initialization {
                channel_id: ChannelId(1),
                command: CommandType::Msg,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7],
                payload_len: 8,
            })
            .await
            .unwrap();

        assert_eq!(
            protocol.next().await.unwrap(),
            Packet::Initialization {
                channel_id: ChannelId(1),
                command: CommandType::Msg,
                data: vec!['m' as u8, 's' as u8, 'g' as u8],
                payload_len: 3,
            }
        );
    }

    #[tokio::test]
    async fn cbor() {
        let mut protocol = Protocol::new(Arc::new(MockApi));

        protocol
            .send(Packet::Initialization {
                channel_id: ChannelId(1),
                command: CommandType::Cbor,
                data: vec![0, 1, 2, 3, 4, 5, 6, 7],
                payload_len: 8,
            })
            .await
            .unwrap();

        assert_eq!(
            protocol.next().await.unwrap(),
            Packet::Initialization {
                channel_id: ChannelId(1),
                command: CommandType::Cbor,
                data: vec!['c' as u8, 'b' as u8, 'o' as u8, 'r' as u8],
                payload_len: 4,
            }
        );
    }

    // TODO: test error handling
    // TODO: test channel management and concurrent sends
}
