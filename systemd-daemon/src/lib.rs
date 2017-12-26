#[macro_use]
extern crate serde_derive;

extern crate bincode;
extern crate bytes;
extern crate slog;
extern crate u2fhid_protocol;

mod definitions;

pub use definitions::*;

pub const SOCKET_PATH: &str = "/run/softu2f/softu2f.sock";
