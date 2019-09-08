use std::collections::vec_deque::VecDeque;
use std::fmt;

use futures::{Async, Poll};
use futures::{AsyncSink, StartSend};
use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{self, Task};

pub trait Segmenter {
    type Item;
    type SegmentedItem;
    fn segment(&self, item: Self::Item) -> VecDeque<Self::SegmentedItem>;
}

#[must_use = "sinks do nothing unless polled"]
pub struct SegmentingSink<S: Sink, G> {
    sink: S,
    buf: VecDeque<S::SinkItem>,
    segmenter: G,
    task: Option<Task>,
}

impl<S, G> SegmentingSink<S, G>
where
    S: Sink,
{
    pub fn new(sink: S, segmenter: G) -> SegmentingSink<S, G> {
        SegmentingSink {
            sink,
            buf: VecDeque::new(),
            segmenter,
            task: None,
        }
    }

    /// Get a shared reference to the inner sink.
    pub fn get_ref(&self) -> &S {
        &self.sink
    }

    /// Get a mutable reference to the inner sink.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    pub fn poll_ready(&mut self) -> Async<()> {
        if self.buf.is_empty() {
            return Async::Ready(());
        }

        self.task = Some(task::current());
        Async::NotReady
    }

    fn try_empty_buffer(&mut self) -> Poll<(), S::SinkError> {
        let mut started_send = false;
        while let Some(item) = self.buf.pop_front() {
            if let AsyncSink::NotReady(item) = self.sink.start_send(item)? {
                self.buf.push_front(item);
                return Ok(Async::NotReady);
            }
            started_send = true;
        }

        // Notify any pending tasks
        if started_send {
            if let Some(task) = self.task.take() {
                task.notify();
            }
        }

        Ok(Async::Ready(()))
    }
}

// Forwarding impl of Stream from the underlying sink
impl<S, G> Stream for SegmentingSink<S, G>
where
    S: Sink + Stream,
{
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<S::Item>, S::Error> {
        self.sink.poll()
    }
}

impl<S, G, T> Sink for SegmentingSink<S, G>
where
    S: Sink,
    G: Segmenter<Item = T, SegmentedItem = S::SinkItem>,
{
    type SinkItem = T;
    type SinkError = S::SinkError;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        if !self.try_empty_buffer()?.is_ready() {
            return Ok(AsyncSink::NotReady(item));
        }

        self.buf.append(&mut self.segmenter.segment(item));

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        let mut flushed = self.try_empty_buffer()?.is_ready();
        flushed &= self.sink.poll_complete()?.is_ready();

        if flushed {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        try_ready!(self.poll_complete());
        self.sink.close()
    }
}

impl<S, G> fmt::Debug for SegmentingSink<S, G>
where
    S: Sink + fmt::Debug,
    S::SinkItem: fmt::Debug,
    G: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SegmentingSink")
            .field("sink", &self.sink)
            .field("buf", &self.buf)
            .field("segmenter", &self.segmenter)
            .field("task", &self.task)
            .finish()
    }
}
