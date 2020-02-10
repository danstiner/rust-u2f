extern crate bincode;
extern crate bytes;
#[macro_use]
extern crate serde_derive;
extern crate slog;
extern crate u2fhid_protocol;

pub use crate::definitions::*;

mod definitions;

pub const DEFAULT_SOCKET_PATH: &str = "/run/softu2f/softu2f.sock";
