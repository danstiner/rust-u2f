use futures::{Sink, SinkExt, Stream, StreamExt};
use pin_project::pin_project;
use tracing::trace;
use u2f_core::Service;

use crate::{protocol_state_machine::StateMachine, Packet, Response};

#[pin_project]
pub struct U2fHidServer<T, S> {
    state_machine: StateMachine<S>,
    #[pin]
    transport: T,
}

impl<T, S, SinkE, StreamE> U2fHidServer<T, S>
where
    T: Sink<Packet, Error = SinkE> + Stream<Item = Result<Packet, StreamE>> + Unpin,
    S: Service<u2f_core::Request, Response = u2f_core::Response>,
{
    pub fn new(transport: T, service: S) -> U2fHidServer<T, S> {
        U2fHidServer {
            state_machine: StateMachine::new(service),
            transport,
        }
    }

    pub async fn serve<E>(mut self) -> Result<(), E>
    where
        E: From<std::io::Error> + From<SinkE>,
    {
        loop {
            trace!("U2fHidServer::poll");

            if let Some(response) = self.state_machine.step()? {
                self.send::<E>(response).await?;
                continue;
            }

            match self.transport.next().await {
                Some(Ok(packet)) => {
                    trace!(?packet, "Got packet from transport");
                    if let Some(response) = self.state_machine.accept_packet(packet)? {
                        self.send::<E>(response).await?;
                    }
                }
                Some(Err(_err)) => todo!(),
                None => todo!("it's closing time"),
            };
        }
    }

    async fn send<E>(&mut self, response: Response) -> Result<(), E>
    where
        E: From<SinkE>,
    {
        trace!(
            channel_id = ?response.channel_id,
            message = ?response.message,
            "Send response"
        );
        for packet in response.into_packets() {
            self.transport.feed(packet).await?;
        }
        self.transport.flush().await?;
        Ok(())
    }
}
