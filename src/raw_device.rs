use std::{fmt, io};

use tokio_io::{AsyncRead, AsyncWrite};
use futures::{Async, AsyncSink, Poll, Stream, Sink, StartSend};
use bytes::{Buf, BytesMut};

/// Decoding of frames via buffers.
///
/// This trait is used when constructing an instance of `Framed` or
/// `FramedRead`. An implementation of `Decoder` takes a byte stream that has
/// already been buffered in `src` and decodes the data into a stream of
/// `Self::Item` frames.
///
/// Implementations are able to track state on `self`, which enables
/// implementing stateful streaming parsers. In many cases, though, this type
/// will simply be a unit struct (e.g. `struct HttpDecoder`).
pub trait Decoder {
    /// The type of decoded frames.
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

/// Trait of helper objects to write out messages as bytes, for use with
/// `FramedWrite`.
pub trait Encoder {
    /// The type of items consumed by the `Encoder`
    type Item;

    /// The type of encoding errors.
    ///
    /// `FramedWrite` requires `Encoder`s errors to implement `From<io::Error>`
    /// in the interest letting it return `Error`s directly.
    type Error: From<io::Error>;

    /// Encodes a frame into the buffer provided.
    ///
    /// This method will encode `msg` into the byte buffer provided by `buf`.
    /// The `buf` provided is an internal buffer of the `Framed` instance and
    /// will be written out when possible.
    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut)
              -> Result<(), Self::Error>;
}

pub struct RawDevice<T, E, D> {
    inner: T,
    encoder: E,
    decoder: D,
}

// ===== impl RawDevice =====

impl<T, E, D> RawDevice<T, E, D>
    where T: AsyncRead + AsyncWrite,
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


impl<T: io::Write, E, D> io::Write for RawDevice<T, E, D> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        self.inner.write(src)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T: AsyncWrite, E, D> AsyncWrite for RawDevice<T, E, D> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.inner.shutdown()
    }

    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        self.inner.write_buf(buf)
    }
}

impl<T, E, D> Stream for RawDevice<T, E, D>
    where T: AsyncRead,
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
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "short read").into())
                }
                let frame = self.decoder.decode(&mut buffer)?;
                return Ok(Async::Ready(Some(frame)));
            },
            Err(e) => return Err(e.into()),
        }
    }
}

impl<T, E, D> Sink for RawDevice<T, E, D>
    where T: AsyncWrite,
          E: Encoder,
{
    type SinkItem = E::Item;
    type SinkError = E::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        let mut buffer = BytesMut::new();
        try!(self.encoder.encode(item, &mut buffer));
        let bytes = buffer.take();

        match self.inner.write(&bytes) {
            Ok(0) =>  Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write frame to transport").into()),
            Ok(n) if n == bytes.len() => Ok(AsyncSink::Ready),
            Ok(_) => Err(io::Error::new(io::ErrorKind::Other, "failed to write entire frame to transport").into()),
            Err(e) => Err(e.into()),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        try_ready!(self.poll_complete());
        Ok(try!(self.inner.shutdown()))
    }
}

impl<T, E, D> fmt::Debug for RawDevice<T, E, D>
    where T: fmt::Debug,
          E: fmt::Debug,
          D: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FramedRead")
            .field("inner", &self.inner)
            .field("encoder", &self.encoder)
            .field("decoder", &self.decoder)
            .finish()
    }
}
