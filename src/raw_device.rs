use std::fmt;
use std::io;
use std::io::Write;

use bytes::BytesMut;
use futures::{Async, Poll, Stream};
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

    /// Decode a frame from the provided buffer of bytes.
    ///
    /// This method is called by `FramedRead` whenever bytes are ready to be
    /// parsed.  The provided buffer of bytes is what's been read so far, and
    /// this instance of `Decode` can determine whether an entire frame is in
    /// the buffer and is ready to be returned.
    ///
    /// If an entire frame is available, then this instance will remove those
    /// bytes from the buffer provided and return them as a decoded
    /// frame. Note that removing bytes from the provided buffer doesn't always
    /// necessarily copy the bytes, so this should be an efficient operation in
    /// most circumstances.
    ///
    /// If the bytes look valid, but a frame isn't fully available yet, then
    /// `Ok(None)` is returned. This indicates to the `Framed` instance that
    /// it needs to read some more bytes before calling this method again.
    ///
    /// Note that the bytes provided may be empty. If a previous call to
    /// `decode` consumed all the bytes in the buffer then `decode` will be
    /// called again until it returns `None`, indicating that more bytes need to
    /// be read.
    ///
    /// Finally, if the bytes in the buffer are malformed then an error is
    /// returned indicating why. This informs `Framed` that the stream is now
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

pub struct RawDevice<T, E, D> {
    inner: T,
    encoder: E,
    decoder: D,
}

// ===== impl RawDevice =====

impl<T, E, D> RawDevice<T, E, D>
where
    T: AsyncRead + Write,
    E: Encoder,
    D: Decoder,
{
    pub fn new(inner: T, encoder: E, decoder: D) -> RawDevice<T, E, D> {
        RawDevice {
            inner: inner,
            encoder: encoder,
            decoder: decoder,
        }
    }
}

impl<T: Write, E, D> Write for RawDevice<T, E, D> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.inner.write(src)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T, E, D> Stream for RawDevice<T, E, D>
where
    T: AsyncRead,
    D: Decoder,
{
    type Item = D::Item;
    type Error = D::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let read_len = self.decoder.read_len();
        let mut buffer = BytesMut::with_capacity(read_len);
        match self.inner.read(&mut buffer) {
            Ok(0) => Ok(Async::Ready(None)),
            Ok(n) => {
                if n != read_len {
                    return Err(
                        io::Error::new(io::ErrorKind::InvalidData, "short read").into(),
                    );
                }
                let frame = self.decoder.decode(&mut buffer)?;
                return Ok(Async::Ready(Some(frame)));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

impl<T, E, D> SyncSink for RawDevice<T, E, D>
where
    T: Write,
    E: Encoder,
{
    type SinkItem = E::Item;
    type SinkError = E::Error;

    fn send(&mut self, item: Self::SinkItem) -> Result<(), Self::SinkError> {
        let mut buffer = BytesMut::new();
        try!(self.encoder.encode(item, &mut buffer));
        let bytes = buffer.take();

        match self.inner.write(&bytes) {
            Ok(0) => Err(
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write item to transport",
                ).into(),
            ),
            Ok(n) if n == bytes.len() => Ok(()),
            Ok(_) => Err(
                io::Error::new(
                    io::ErrorKind::Other,
                    "failed to write entire item to transport",
                ).into(),
            ),
            Err(e) => Err(e.into()),
        }
    }
}

impl<T, E, D> fmt::Debug for RawDevice<T, E, D>
where
    T: fmt::Debug,
    E: fmt::Debug,
    D: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RawDevice")
            .field("inner", &self.inner)
            .field("encoder", &self.encoder)
            .field("decoder", &self.decoder)
            .finish()
    }
}
