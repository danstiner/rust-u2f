use std::io;
use futures::{Stream, Sink, Async};
use tokio_io as new_io;

mod client;
pub use self::client::ClientProto;

mod server;
pub use self::server::ServerProto;

mod frame;
pub use self::frame::Frame;

mod transport;
pub use self::transport::Transport;

pub mod advanced;

pub type ChannelId = u64;

/// A marker used to flag protocols as TODO.
///
/// This is an implementation detail; to actually implement a protocol,
/// implement the `ClientProto` or `ServerProto` traits in this module.
#[derive(Debug)]
pub struct SegmentedMultichannel<B>(B);
