//! # Tokio UHID
//!
//! A safe wrapper around the userspace API to the HID subsystem in the linux kernel.
//!
//! See https://www.kernel.org/doc/Documentation/hid/uhid.txt
//!
//! ## Example
//! ```rust,no_run
//!#  extern crate futures;
//!#  extern crate tokio;
//!#  extern crate tokio_linux_uhid;
//! 
//! use tokio_linux_uhid::{Bus, CreateParams, UHIDDevice};
//! 
//! // Formulate a 'HID Report Descriptor' to describe the function of your device.
//! // This tells the kernel how to interpret the HID packets you send to the device.
//! const RDESC: [u8; 85] = [
//!     0x05, 0x01,	/* USAGE_PAGE (Generic Desktop) */
//!     0x09, 0x02,	/* USAGE (Mouse) */
//!     0xa1, 0x01,	/* COLLECTION (Application) */
//!     0x09, 0x01,		/* USAGE (Pointer) */
//!     0xa1, 0x00,		/* COLLECTION (Physical) */
//!     0x85, 0x01,			/* REPORT_ID (1) */
//!     0x05, 0x09,			/* USAGE_PAGE (Button) */
//!     0x19, 0x01,			/* USAGE_MINIMUM (Button 1) */
//!     0x29, 0x03,			/* USAGE_MAXIMUM (Button 3) */
//!     0x15, 0x00,			/* LOGICAL_MINIMUM (0) */
//!     0x25, 0x01,			/* LOGICAL_MAXIMUM (1) */
//!     0x95, 0x03,			/* REPORT_COUNT (3) */
//!     0x75, 0x01,			/* REPORT_SIZE (1) */
//!     0x81, 0x02,			/* INPUT (Data,Var,Abs) */
//!     0x95, 0x01,			/* REPORT_COUNT (1) */
//!     0x75, 0x05,			/* REPORT_SIZE (5) */
//!     0x81, 0x01,			/* INPUT (Cnst,Var,Abs) */
//!     0x05, 0x01,			/* USAGE_PAGE (Generic Desktop) */
//!     0x09, 0x30,			/* USAGE (X) */
//!     0x09, 0x31,			/* USAGE (Y) */
//!     0x09, 0x38,			/* USAGE (WHEEL) */
//!     0x15, 0x81,			/* LOGICAL_MINIMUM (-127) */
//!     0x25, 0x7f,			/* LOGICAL_MAXIMUM (127) */
//!     0x75, 0x08,			/* REPORT_SIZE (8) */
//!     0x95, 0x03,			/* REPORT_COUNT (3) */
//!     0x81, 0x06,			/* INPUT (Data,Var,Rel) */
//!     0xc0,			/* END_COLLECTION */
//!     0xc0,		/* END_COLLECTION */
//!     0x05, 0x01,	/* USAGE_PAGE (Generic Desktop) */
//!     0x09, 0x06,	/* USAGE (Keyboard) */
//!     0xa1, 0x01,	/* COLLECTION (Application) */
//!     0x85, 0x02,		/* REPORT_ID (2) */
//!     0x05, 0x08,		/* USAGE_PAGE (Led) */
//!     0x19, 0x01,		/* USAGE_MINIMUM (1) */
//!     0x29, 0x03,		/* USAGE_MAXIMUM (3) */
//!     0x15, 0x00,		/* LOGICAL_MINIMUM (0) */
//!     0x25, 0x01,		/* LOGICAL_MAXIMUM (1) */
//!     0x95, 0x03,		/* REPORT_COUNT (3) */
//!     0x75, 0x01,		/* REPORT_SIZE (1) */
//!     0x91, 0x02,		/* Output (Data,Var,Abs) */
//!     0x95, 0x01,		/* REPORT_COUNT (1) */
//!     0x75, 0x05,		/* REPORT_SIZE (5) */
//!     0x91, 0x01,		/* Output (Cnst,Var,Abs) */
//!     0xc0,		/* END_COLLECTION */
//! ];
//! 
//! fn main() {
//!     let mut uhid_device = UHIDDevice::create(CreateParams {
//!         name: String::from("test-uhid-device"),
//!         phys: String::from(""),
//!         uniq: String::from(""),
//!         bus: Bus::USB,
//!         vendor: 0x15d9,
//!         product: 0x0a37,
//!         version: 0,
//!         country: 0,
//!         // Most important field - HID Report Descriptor
//!         data: RDESC.to_vec(),
//!     }, None).unwrap();
//! 
//!     // Formulate a HID Packet
//!     let button_flags = 0;
//!     let mouse_abs_hor = 20;
//!     let mouse_abs_ver = 0;
//!     let wheel = 0;
//!     let data: [u8; 5] = [1, button_flags, mouse_abs_hor, mouse_abs_ver, wheel];
//!     
//!     // Send the HID packet to the device. Cursor should move 20 points to the right. 
//!     uhid_device.send_input(&data).unwrap();
//! }
//! ```
#[macro_use]
extern crate bitflags;
extern crate bytes;
extern crate futures;
extern crate mio;
extern crate nix;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate slog;
extern crate slog_stdlog;
extern crate tokio;
extern crate tokio_io;
extern crate uhid_sys;

pub use codec::{Bus, InputEvent, OutputEvent, StreamError};
pub use uhid_device::CreateParams;
pub use uhid_device::UHIDDevice;

mod character_device;
mod codec;
mod misc_driver;
mod transport;
mod uhid_device;
