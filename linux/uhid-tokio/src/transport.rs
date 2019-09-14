use std::fmt;
use std::io;
use std::io::Write;

use bytes::buf::FromBuf;
use bytes::BytesMut;
use futures::{Async, Poll, Stream};
use slog;
use tokio_io::AsyncRead;

/// Decoding of items in buffers.
///
/// An implementation of `Decoder` takes a buffer of bytes and is expected
/// to decode exactly one item. Any other result should be considered an error.
///
/// Implementations are able to track state on `self`.
pub trait Decoder {
    /// The type of decoded items.
    type Item;

    /// The type of unrecoverable frame decoding errors.
    ///
    /// If an individual message is ill-formed but can be ignored without
    /// interfering with the processing of future messages, it may be more
    /// useful to report the failure as an `Item`.
    ///
    /// `From<io::Error>` is required in the interest of making `Error` suitable
    /// for returning directly from a `FramedRead`, and to enable the default
    /// implementation of `decode_eof` to yield an `io::Error` when the decoder
    /// fails to consume all available data.
    ///
    /// Note that implementors of this trait can simply indicate `type Error =
    /// io::Error` to use I/O errors as this type.
    type Error: From<io::Error>;

    /// Decode an item from the provided buffer of bytes.
    ///
    /// The length of the buffer will exactly match the number of bytes
    /// returned by the last call made to `read_len`.
    ///
    /// If the bytes in the buffer are malformed then an error is
    /// returned indicating why. This indicates the stream is now
    /// corrupt and should be terminated.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Self::Item, Self::Error>;

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
    logger: slog::Logger,
}

impl<T, E, D> Transport<T, E, D>
    where
        T: AsyncRead + Write,
        E: Encoder,
        D: Decoder,
{
    pub fn new(inner: T, encoder: E, decoder: D, logger: slog::Logger) -> Transport<T, E, D> {
        Transport {
            decoder,
            encoder,
            inner,
            logger,
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
    type Error = D::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let read_len = self.decoder.read_len();
        let mut buffer = vec![0u8; read_len];
        match self.inner.read(&mut buffer[..]) {
            Ok(0) => {
                trace!(self.logger, "CharacterDevice::Stream::poll => Ok");
                Ok(Async::Ready(None))
            }
            Ok(n) => {
                if n != read_len {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "short read").into());
                }
                let bytes = &mut BytesMut::from_buf(buffer);
                trace!(self.logger, "CharacterDevice::Stream::poll => Ok"; "bytes" => ?&bytes);
                let frame = self.decoder.decode(bytes)?;
                Ok(Async::Ready(Some(frame)))
            }
            Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => {
                trace!(self.logger, "CharacterDevice::Stream::poll => WouldBlock");
                Ok(Async::NotReady)
            }
            Err(e) => {
                trace!(self.logger, "CharacterDevice::Stream::poll => Err");
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
        let bytes = buffer.take();

        trace!(self.logger, "CharacterDevice::SyncSink::send"; "bytes" => ?&bytes);

        match self.inner.write(&bytes) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write item to transport",
            ).into()),
            Ok(n) if n == bytes.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to write entire item to transport",
            ).into()),
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
