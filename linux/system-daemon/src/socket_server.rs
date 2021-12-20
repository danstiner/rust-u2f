use std::fmt;
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
use tracing::debug;
use tracing::error;
use tracing::trace;

#[must_use = "futures do nothing unless polled"]
#[pin_project]
#[derive(Debug)]
pub struct SocketServer<S>
where
    S: Service<(UnixStream, SocketAddr)>,
{
    listener: UnixListener,
    make_stream_handler: S,
}

impl<S> SocketServer<S>
where
    S: Service<(UnixStream, SocketAddr)>,
{
    pub fn serve(listener: UnixListener, make_stream_handler: S) -> Self {
        SocketServer {
            listener,
            make_stream_handler,
        }
    }
}

impl<S, Handler, E> Future for SocketServer<S>
where
    S: Service<(UnixStream, SocketAddr), Response = Handler, Error = E>,
    S::Future: Send + 'static,
    Handler: Future + Send,
    Handler::Output: Send + fmt::Debug,
    E: From<io::Error> + Send + fmt::Debug,
{
    type Output = Result<(), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        loop {
            // Check we have available capacity to create a handler instance
            // before accepting a stream.
            if this.make_stream_handler.poll_ready(cx).is_pending() {
                trace!("Not ready to accept streams");
                return Poll::Pending;
            }

            // Accept a connection on the socket and spawn a service instance to respond.
            // Repeats if successful, returns if there is an error or no connections are availabile.
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, addr))) => {
                    trace!(?addr, "SocketServer: accepted stream");
                    let handler_future = this.make_stream_handler.call((stream, addr));
                    spawn_named("stream handler", async {
                        trace!("SocketServer: Spawned handler for stream");
                        match handler_future.await {
                            Ok(handler) => {
                                trace!("Handler ready, waiting for it to complete");
                                let res = handler.await;
                                debug!(?res, "Spawned handler finished with: {:?}", res);
                                todo!()
                            }
                            Err(err) => {
                                error!(?err, "Error from spawned task");
                                todo!()
                            }
                        };
                    });
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn spawn_named<T>(
    _name: &str,
    task: impl std::future::Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T>
where
    T: Send + 'static,
{
    #[cfg(tokio_unstable)]
    return tokio::task::Builder::new().name(_name).spawn(task);

    #[cfg(not(tokio_unstable))]
    tokio::spawn(task)
}
