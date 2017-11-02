use super::ChannelId;

/// A multiplexed protocol frame
#[derive(Debug, Clone)]
pub enum Frame<T, B, N, E> {
    /// Either a request or a response.
    Initial {
        /// Message exchange identifier
        channel_id: ChannelId,
        /// The message value
        message: T,
    },
    /// Continuation frame.
    Continuation {
        /// Message exchange identifier
        channel_id: ChannelId,
        sequence_number: N,
        /// Body chunk. Setting to `None` indicates that the body is done
        /// streaming and there will be no further body frames sent with the
        /// given request ID.
        chunk: Option<B>,
    },
    /// Error
    Error {
        /// Message exchange identifier
        id: RequestId,
        /// Error value
        error: E,
    },
}

impl<T, B, E> Frame<T, B, E> {
    /// Return the request ID associated with the frame.
    pub fn channel_id(&self) -> RequestId {
        match *self {
            Frame::Message { id, .. } => id,
            Frame::Body { id, .. } => id,
            Frame::Error { id, .. } => id,
        }
    }

    /// Unwraps a frame, yielding the content of the `Message`.
    pub fn unwrap_msg(self) -> T {
        match self {
            Frame::Message { message, .. } => message,
            Frame::Body { .. } => panic!("called `Frame::unwrap_msg()` on a `Body` value"),
            Frame::Error { .. } => panic!("called `Frame::unwrap_msg()` on an `Error` value"),
        }
    }

    /// Unwraps a frame, yielding the content of the `Body`.
    pub fn unwrap_body(self) -> Option<B> {
        match self {
            Frame::Body { chunk, .. } => chunk,
            Frame::Message { .. } => panic!("called `Frame::unwrap_body()` on a `Message` value"),
            Frame::Error { .. } => panic!("called `Frame::unwrap_body()` on an `Error` value"),
        }
    }

    /// Unwraps a frame, yielding the content of the `Error`.
    pub fn unwrap_err(self) -> E {
        match self {
            Frame::Error { error, .. } => error,
            Frame::Body { .. } => panic!("called `Frame::unwrap_err()` on a `Body` value"),
            Frame::Message { .. } => panic!("called `Frame::unwrap_err()` on a `Message` value"),
        }
    }
}