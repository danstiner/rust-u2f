extern crate bitflags;
extern crate byteorder;
extern crate futures;
extern crate itertools;
extern crate serde_derive;
extern crate serde;
extern crate thiserror;
extern crate tokio_core;
extern crate tokio_tower;
extern crate tracing;
extern crate u2f_core;

use std::collections::vec_deque::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

pub use crate::definitions::Packet;
use crate::definitions::*;
// use crate::protocol_state_machine::StateMachine;
use futures::{Future, Sink, Stream};
use tokio_tower::pipeline::Server;
use tracing::trace;
use u2f_core::{Service};

mod definitions;
// mod protocol_state_machine;
