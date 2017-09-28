#[macro_use]
extern crate bitflags;
extern crate bytes;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate quick_error;
extern crate tokio_core;
#[macro_use]
extern crate tokio_io;
extern crate tokio_file_unix;

mod raw_device;
mod uhid_codec;
mod uhid_device;

pub use uhid_device::UHIDDevice;
pub use uhid_device::CreateParams;
pub use uhid_codec::Bus;
