#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate slog;
#[macro_use]
extern crate quick_error;

extern crate bytes;
extern crate futures;
extern crate linux_uhid_sys;
extern crate mio;
extern crate nix;
extern crate slog_stdlog;
extern crate tokio_core;
extern crate tokio_io;

mod character_device_file;
mod character_device;
mod uhid_codec;
mod uhid_device;
mod poll_evented_read_wrapper;

pub use uhid_device::UHIDDevice;
pub use uhid_device::CreateParams;
pub use uhid_codec::{Bus, InputEvent, OutputEvent, StreamError};
