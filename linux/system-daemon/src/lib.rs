extern crate bincode;
extern crate bytes;
extern crate serde_derive;

pub use crate::definitions::*;

mod definitions;

pub const DEFAULT_SOCKET_PATH: &str = "/run/softu2f/softu2f.sock";
