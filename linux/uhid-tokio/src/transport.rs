use std::fmt;
use std::io;
use std::io::Write;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use bytes::BytesMut;
use futures::prelude::*;
use tracing::trace;

/// Decoding of items in buffers.
///
/// An implementation of `Decoder` takes a buffer of bytes and is expected
/// to decode exactly one item. Any other result should be considered an error.
///
/// Implementations are able to track state on `self`.
pub trait Decoder {
    /// The type of decoded items.
    type Item;

    /// Decode an item from the provided buffer of bytes.
    ///
    /// The length of the buffer will exactly match the number of bytes
    /// returned by the last call made to `read_len`.
    fn decode(&mut self, src: &mut BytesMut) -> Self::Item;

    fn read_len(&self) -> usize;
}

/// Trait of helper objects to write out items as bytes.
pub trait Encoder {
    /// The type of items consumed by the `Encoder`
    type Item;

    /// The type of encoding errors.
    ///
    /// Required to implement `From<io::Error>` so it can be
    /// used as the error type of a Sink that does I/O.
    type Error: From<io::Error>;

    /// Encodes an item into the buffer provided.
    ///
    /// This method will encode `item` into the byte buffer provided by `buf`.
    /// The `buf` provided may be re-used for subsequent encodings.
    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error>;
}

/// Synchronous sink for items
pub trait SyncSink {
    type SinkItem;
    type SinkError;

    fn send(&mut self, item: Self::SinkItem) -> Result<(), Self::SinkError>;

    fn close(&mut self) -> Result<(), Self::SinkError> {
        Ok(())
    }
}

pub struct Transport<T, E, D> {
    inner: T,
    encoder: E,
    decoder: D,
}

impl<T, E, D> Transport<T, E, D>
where
    T: AsyncRead + Write,
    E: Encoder,
    D: Decoder,
{
    pub fn new(inner: T, encoder: E, decoder: D) -> Transport<T, E, D> {
        Transport {
            decoder,
            encoder,
            inner,
        }
    }
}

impl<T: Write, E, D> Write for Transport<T, E, D> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.inner.write(src)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T, E, D> Stream for Transport<T, E, D>
where
    T: AsyncRead,
    D: Decoder,
{
    type Item = D::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let read_len = self.decoder.read_len();
        let mut buffer = BytesMut::with_capacity(read_len);
        buffer.resize(read_len, 0u8);
        match self.inner.read(&mut buffer) {
            Ok(0) => {
                trace!("Transport::poll_next => Ok");
                Ok(Poll::Ready(None))
            }
            Ok(n) => {
                if n != read_len {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "short read").into());
                }
                buffer.resize(n, 0u8);
                trace!(bytes = ?buffer, "Transport::poll_next => Ok");
                let frame = self.decoder.decode(&mut buffer)?;
                Ok(Poll::Ready(Some(frame)))
            }
            Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => {
                trace!("Transport::poll_next => WouldBlock");
                Ok(Poll::NotReady)
            }
            Err(e) => {
                trace!("Transport::poll_next => Err");
                Err(e.into())
            }
        }
    }
}

impl<T, E, D> SyncSink for Transport<T, E, D>
where
    T: Write,
    E: Encoder,
{
    type SinkItem = E::Item;
    type SinkError = E::Error;

    fn send(&mut self, item: Self::SinkItem) -> Result<(), Self::SinkError> {
        let mut buffer = BytesMut::new();
        self.encoder.encode(item, &mut buffer)?;

        trace!(bytes = ?buffer, "Transport::send");

        match self.inner.write(&buffer) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write item to transport",
            )
            .into()),
            Ok(n) if n == buffer.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to write entire item to transport",
            )
            .into()),
            Err(e) => Err(e.into()),
        }
    }
}

impl<T, E, D> fmt::Debug for Transport<T, E, D>
where
    T: fmt::Debug,
    E: fmt::Debug,
    D: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CharacterDevice")
            .field("inner", &self.inner)
            .field("encoder", &self.encoder)
            .field("decoder", &self.decoder)
            .finish()
    }
}
