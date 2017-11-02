use std::io;
use futures::{Stream, Sink, Async};
use tokio_io;

/// Additional transport details relevant to streaming, multiplexed protocols.
///
/// All methods added in this trait have default implementations.
pub trait Transport<ReadBody>: 'static +
    Stream<Error = io::Error> +
    Sink<SinkError = io::Error>
{
    /// Allow the transport to do miscellaneous work (e.g., sending ping-pong
    /// messages) that is not directly connected to sending or receiving frames.
    ///
    /// This method should be called every time the task using the transport is
    /// executing.
    fn tick(&mut self) {}
}

impl<T, C, ReadBody> Transport<ReadBody> for tokio_io::codec::Framed<T,C>
    where T: tokio_io::AsyncRead + tokio_io::AsyncWrite + 'static,
          C: tokio_io::codec::Encoder<Error=io::Error> +
                tokio_io::codec::Decoder<Error=io::Error> + 'static,
{}
