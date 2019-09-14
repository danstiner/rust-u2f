use std::marker::PhantomData;

use futures::prelude::*;

pub struct BidirectionalPipe<A, B, E>
where
    A: Stream,
    B: Stream,
{
    buffer_a: Option<A::Item>,
    buffer_b: Option<B::Item>,
    side_a: A,
    side_b: B,
    stream_a_finished: bool,
    stream_b_finished: bool,
    _error_type: PhantomData<E>,
}

impl<A, B, E> BidirectionalPipe<A, B, E>
where
    A: Stream,
    B: Stream,
{
    pub fn new(side_a: A, side_b: B) -> BidirectionalPipe<A, B, E> {
        BidirectionalPipe {
            buffer_a: None,
            buffer_b: None,
            side_a,
            side_b,
            stream_a_finished: false,
            stream_b_finished: false,
            _error_type: PhantomData,
        }
    }
}

impl<A, B, E> Future for BidirectionalPipe<A, B, E>
where
    A: Stream + Sink<SinkItem = <B as Stream>::Item>,
    B: Stream + Sink<SinkItem = <A as Stream>::Item>,
    A::Error: Into<E>,
    B::Error: Into<E>,
    A::SinkError: Into<E>,
    B::SinkError: Into<E>,
{
    type Item = ();
    type Error = E;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let mut made_progress = false;

            // Buffer items to send if any are available
            if self.buffer_a.is_none() && !self.stream_a_finished {
                match self.side_a.poll() {
                    Ok(Async::Ready(Some(item))) => self.buffer_a = Some(item),
                    Ok(Async::Ready(None)) => self.stream_a_finished = true,
                    Ok(Async::NotReady) => {}
                    Err(err) => return Err(err.into()),
                }
            }
            if self.buffer_b.is_none() && !self.stream_b_finished {
                match self.side_b.poll() {
                    Ok(Async::Ready(Some(item))) => self.buffer_b = Some(item),
                    Ok(Async::Ready(None)) => self.stream_b_finished = true,
                    Ok(Async::NotReady) => {}
                    Err(err) => return Err(err.into()),
                }
            }

            // Send any buffered items, piped to opposing side
            if let Some(item) = self.buffer_a.take() {
                match self.side_b.start_send(item) {
                    Ok(AsyncSink::Ready) => made_progress = true,
                    Ok(AsyncSink::NotReady(rejected_item)) => self.buffer_a = Some(rejected_item),
                    Err(err) => return Err(err.into()),
                };
            }
            if let Some(item) = self.buffer_b.take() {
                match self.side_a.start_send(item) {
                    Ok(AsyncSink::Ready) => made_progress = true,
                    Ok(AsyncSink::NotReady(rejected_item)) => self.buffer_b = Some(rejected_item),
                    Err(err) => return Err(err.into()),
                };
            }

            // Check for completion of all parts of the pipe before completing future
            let sink_a_flushed = match self.side_a.poll_complete() {
                Ok(Async::Ready(())) => true,
                Ok(Async::NotReady) => false,
                Err(err) => return Err(err.into()),
            };
            let sink_b_flushed = match self.side_b.poll_complete() {
                Ok(Async::Ready(())) => true,
                Ok(Async::NotReady) => false,
                Err(err) => return Err(err.into()),
            };
            let streams_finished = self.stream_a_finished && self.stream_b_finished;
            let sinks_flushed = sink_a_flushed && sink_b_flushed;
            let no_items_buffered = self.buffer_a.is_none() && self.buffer_b.is_none();

            // Exit loop if complete or no progress was made
            if streams_finished && sinks_flushed && no_items_buffered {
                return Ok(Async::Ready(()));
            }
            if !made_progress {
                return Ok(Async::NotReady);
            }
        }
    }
}
