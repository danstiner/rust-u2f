use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use futures::Future;
use pin_project::pin_project;
use tokio::net::unix::SocketAddr;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tower::Service;

#[must_use = "futures do nothing unless polled"]
#[pin_project]
#[derive(Debug)]
pub struct SocketServer<H>
where
    H: Service<(UnixStream, SocketAddr)>,
{
    listener: UnixListener,
    connection_handler: H,
}

impl<H> SocketServer<H>
where
    H: Service<(UnixStream, SocketAddr)>,
{
    pub fn serve(listener: UnixListener, connection_handler: H) -> Self {
        SocketServer {
            listener,
            connection_handler,
        }
    }
}

impl<H, Connection, E> Future for SocketServer<H>
where
    H: Service<(UnixStream, SocketAddr), Response = Connection, Error = E>,
    H::Future: Send + 'static,
    Connection: Future + Send,
    Connection::Output: Send,
    E: From<io::Error> + Send,
{
    type Output = Result<(), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        loop {
            // Check we have available capacity to create a service instance
            // before accepting a connection.
            if this.connection_handler.poll_ready(cx).is_pending() {
                return Poll::Pending;
            }

            // Accept a connection on the socket and spawn a service instance to respond.
            // Repeats if successful, returns if there is an error or no connections are availabile.
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok(connection)) => {
                    let connection = this.connection_handler.call(connection);
                    tokio::spawn(async {
                        match connection.await {
                            Ok(connection) => connection.await,
                            Err(_err) => todo!(),
                        };
                    });
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
