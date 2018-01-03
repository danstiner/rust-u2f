#[macro_use]
extern crate bitflags;
extern crate bytes;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate quick_error;
extern crate mio;
extern crate nix;
#[macro_use]
extern crate slog;
extern crate slog_stdlog;
extern crate tokio_core;
extern crate tokio_io;
extern crate uhid_linux_sys;

mod character_device_file;
mod character_device;
mod uhid_codec;
mod uhid_device;
mod poll_evented_read_wrapper;

pub use uhid_device::UHIDDevice;
pub use uhid_device::CreateParams;
pub use uhid_codec::{Bus, InputEvent, OutputEvent, StreamError};
