use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use futures::Future;
use tokio::net::unix::SocketAddr;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tower::make::MakeService;

#[must_use = "futures do nothing unless polled"]
#[derive(Debug)]
pub struct SocketServer<S, R>
where
    S: MakeService<(UnixStream, SocketAddr), R>,
{
    listener: UnixListener,
    make_service: S,
    _request_type: PhantomData<R>,
}

impl<S, R> SocketServer<S, R>
where
    S: MakeService<(UnixStream, SocketAddr), R>,
{
    pub fn serve(listener: UnixListener, make_service: S) -> Self {
        SocketServer {
            listener,
            make_service,
            _request_type: PhantomData,
        }
    }
}

impl<S, R> Future for SocketServer<S, R>
where
    S: MakeService<(UnixStream, SocketAddr), R> + Unpin,
    S::Service: Send + 'static,
    S::Future: Send + 'static,
    S::MakeError: Send + 'static,
    R: Unpin,
{
    type Output = Result<(), io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Check we have available capacity to create a service instance
            // before accepting a connection.
            if self.make_service.poll_ready(cx).is_pending() {
                return Poll::Pending;
            }

            // Accept a connection on the socket and spawn a service instance to respond.
            // Repeats if successful, returns if there is an error or no connections are availabile.
            match self.listener.poll_accept(cx) {
                Poll::Ready(Ok(connection)) => {
                    tokio::spawn(self.make_service.make_service(connection));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
