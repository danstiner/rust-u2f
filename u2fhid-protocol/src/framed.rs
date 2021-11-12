use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use pin_project::pin_project;

pub trait Decoder {
    type Item;
    type Decoded;
    type Error;

    fn decode(&mut self, item: &mut Self::Item) -> Result<Option<Self::Decoded>, Self::Error>;
}

pub trait Encoder {
    type Item;
    type Encoded;
    type Error;

    fn encode(&mut self, item: &mut Self::Item) -> Result<Option<Self::Encoded>, Self::Error>;
}

#[pin_project]
pub struct Framed<T, P> {
    #[pin]
    transport: T,
    protocol: P,
}

impl<T, P, I, E> Framed<T, P>
where
    T: Stream<Item = Result<I, E>>,
    P: Decoder<Item = I, Error = E>,
{
    pub fn new(transport: T, protocol: P) -> Self {
        Self {
            transport,
            protocol,
        }
    }
}

impl<T, P, I, E> Stream for Framed<T, P>
where
    T: Stream<Item = Result<I, E>>,
    P: Decoder<Item = I, Error = E>,
{
    type Item = Result<P::Decoded, P::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().transport.poll_next(cx);
        todo!()
    }
}

impl<T, P, O, E> Sink<P::Item> for Framed<T, P>
where
    T: Sink<O, Error = E>,
    P: Encoder<Encoded = O, Error = E>,
{
    type Error = E;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().transport.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: P::Item) -> Result<(), Self::Error> {
        self.project().transport.start_send(todo!())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().transport.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().transport.poll_close(cx)
    }
}
