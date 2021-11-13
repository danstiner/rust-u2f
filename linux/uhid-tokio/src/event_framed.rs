use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use bytes::BytesMut;
use futures::prelude::*;
use futures::ready;
use pin_project::pin_project;
use tracing::trace;

/// Decoding of items in buffers.
///
/// An implementation of `Decoder` takes a buffer of bytes and is expected
/// to decode exactly one item. Any other result should be considered an error.
pub trait Decoder {
    /// The type of decoded items.
    type Item;

    type Error: From<io::Error>;

    /// Decode an item from the provided buffer of bytes.
    ///
    /// The length of the buffer will exactly match the number of bytes
    /// returned by the last call made to `read_len`.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Self::Item, Self::Error>;

    fn read_len(&self) -> usize;
}

/// Encoding items into byte buffers.
///
/// An implementation of `Encoder` takes an item and encodes it into buffer of bytes.
pub trait Encoder<Item> {
    /// The type of encoding errors.
    ///
    /// Required to implement `From<io::Error>` so it can be
    /// used as the error type of a Sink that does I/O.
    type Error: From<io::Error>;

    /// Encodes an item into the buffer provided.
    ///
    /// This method will encode `item` into the byte buffer provided by `buf`.
    /// The `buf` provided may be re-used for subsequent encodings.
    fn encode(&mut self, item: Item, dst: &mut BytesMut) -> Result<(), Self::Error>;
}

// Frame reads and writes to transport using a codec.
// Unlike the tokio Framed struct, it is meant to read fixed size event structs from a character device.
// The decoder says how large the read buffer should be, and each read is expected to decode to a stream output.
// Reads are not buffered and combined until the encoder is happy like the Framed struct does.
#[pin_project]
pub struct EventFramed<T, C> {
    #[pin]
    transport: T,
    codec: C,
    write_buffer: Option<BytesMut>,
}

impl<T, C> EventFramed<T, C> {
    pub fn new(transport: T, codec: C) -> EventFramed<T, C> {
        EventFramed {
            transport,
            codec,
            write_buffer: None,
        }
    }
}

impl<T, Codec> Stream for EventFramed<T, Codec>
where
    T: AsyncRead + Unpin,
    Codec: Decoder,
{
    type Item = Result<Codec::Item, Codec::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        let read_len = this.codec.read_len();
        let mut buf = BytesMut::with_capacity(read_len);

        buf.resize(read_len, 0u8);
        let n = ready!(Pin::new(&mut this.transport).poll_read(cx, &mut buf))?;
        buf.resize(n, 0u8);

        trace!(bytes = ?buf, "EventFramed::poll_next");
        let item = this.codec.decode(&mut buf)?;
        Poll::Ready(Some(Ok(item)))
    }
}

impl<T, C, Item> Sink<Item> for EventFramed<T, C>
where
    T: AsyncWrite + Unpin,
    C: Encoder<Item>,
{
    type Error = C::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();

        if let Some(buf) = this.write_buffer.take() {
            match this.transport.poll_write(cx, &buf) {
                Poll::Ready(Ok(n)) => {
                    if n != buf.len() {
                        return Poll::Ready(Err(todo!()));
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                Poll::Pending => {
                    debug_assert!(this.write_buffer.replace(buf).is_none());
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        let this = self.project();
        let mut buf = BytesMut::new();
        this.codec.encode(item, &mut buf)?;
        debug_assert!(this.write_buffer.replace(buf).is_none());
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.project().transport.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        ready!(Pin::new(&mut this.transport).poll_flush(cx))?;
        ready!(this.transport.poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<T, Codec> fmt::Debug for EventFramed<T, Codec>
where
    T: fmt::Debug,
    Codec: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EventFramed")
            .field("transport", &self.transport)
            .field("codec", &self.codec)
            .finish()
    }
}
