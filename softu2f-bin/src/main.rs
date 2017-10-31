extern crate futures;
extern crate rprompt;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate tokio_core;
extern crate u2f_core;
extern crate u2fhid_transport;
extern crate uhid_linux_tokio;
extern crate tokio_io;

use std::ascii::AsciiExt;
use std::io;

use futures::{future, Future, Stream, Sink};
use slog::*;
use tokio_core::reactor::Core;

use u2f_core::{ApplicationParameter, UserPresence, InMemoryStorage, SecureCryptoOperations, U2F};
use u2fhid_transport::{Packet, U2FHID};
use uhid_linux_tokio::{Bus, CreateParams, UHIDDevice, InputEvent, OutputEvent, StreamError};

struct CommandPromptUserPresence;

impl CommandPromptUserPresence {
    fn approve(prompt: &str) -> io::Result<bool> {
        loop {
            let reply = rprompt::prompt_reply_stdout(prompt)?;
            if reply.eq_ignore_ascii_case("y") {
                return Ok(true);
            } else if reply.eq_ignore_ascii_case("n") {
                return Ok(false);
            }
        }
    }
}

impl UserPresence for CommandPromptUserPresence {
    fn approve_registration(&self, _: &ApplicationParameter) -> io::Result<bool> {
        Self::approve("Approve registration [y/n]: ")
    }

    fn approve_authentication(&self, _: &ApplicationParameter) -> io::Result<bool> {
        Self::approve("Approve authentication [y/n]: ")
    }

    fn wink(&self) -> io::Result<()> {
        println!(";)");
        Ok(())
    }
}

fn output_to_packet(output_event: OutputEvent) -> Option<Packet> {
    match output_event {
        OutputEvent::Output { data } => Some(Packet::from_bytes(&data).unwrap()),
        _ => None,
    }
}

fn packet_to_input(packet: Packet) -> Box<Future<Item = InputEvent, Error = StreamError>> {
    Box::new(future::ok(InputEvent::Input { data: packet.into_bytes() }))
}

fn stream_error_to_io_error(err: StreamError) -> io::Error {
    match err {
        StreamError::Io(err) => err,
        StreamError::UnknownEventType(event_type_value) => {
            io::Error::new(io::ErrorKind::Other, "Unknown event type")
        }
        StreamError::BufferOverflow(data_size, max_size) => {
            io::Error::new(io::ErrorKind::Other, "Buffer overflow")
        }
        StreamError::Nul(err) => io::Error::new(io::ErrorKind::Other, err),
        StreamError::Unknown => io::Error::new(io::ErrorKind::Other, "Unknown"),
    }
}

const INPUT_REPORT_LEN: u8 = 64;
const OUTPUT_REPORT_LEN: u8 = 64;

// HID Report Descriptor from http://www.usb.org/developers/hidpage/HUTRR48.pdf
const REPORT_DESCRIPTOR: [u8; 34] = [
        0x06, 0xd0, 0xf1,             // USAGE_PAGE (FIDO Alliance)
        0x09, 0x01,                   // USAGE (Keyboard)
        0xa1, 0x01,                   // COLLECTION (Application)
        0x09, 0x20,                   //   USAGE (Input Report Data)
        0x15, 0x00,                   //   LOGICAL_MINIMUM (0)
        0x26, 0xff, 0x00,             //   LOGICAL_MAXIMUM (255)
        0x75, 0x08,                   //   REPORT_SIZE (8)
        0x95, INPUT_REPORT_LEN,       //   REPORT_COUNT (64)
        0x81, 0x02,                   //   INPUT (Data,Var,Abs)
        0x09, 0x21,                   //   USAGE(Output Report Data)
        0x15, 0x00,                   //   LOGICAL_MINIMUM (0)
        0x26, 0xff, 0x00,             //   LOGICAL_MAXIMUM (255)
        0x75, 0x08,                   //   REPORT_SIZE (8)
        0x95, OUTPUT_REPORT_LEN,      //   REPORT_COUNT (64)
        0x91, 0x02,                   //   OUTPUT (Data,Var,Abs)
        0xc0,                         // END_COLLECTION
];

fn run(logger: slog::Logger) -> io::Result<()> {
    let create_params = CreateParams {
        name: String::from("SoftU2F-Linux"),
        phys: String::from(""),
        uniq: String::from(""),
        bus: Bus::USB,
        vendor: 0xffff,
        product: 0xffff,
        version: 0,
        country: 0,
        data: REPORT_DESCRIPTOR.to_vec(),
    };

    let mut core = Core::new()?;
    let handle = core.handle();

    let uhid_device = UHIDDevice::create(&handle, create_params, logger.new(o!()))?;
    let transport = uhid_device
        .filter_map(output_to_packet)
        .with(packet_to_input)
        .map_err(stream_error_to_io_error)
        .sink_map_err(stream_error_to_io_error);

    let attestation = u2f_core::self_signed_attestation();
    let approval = CommandPromptUserPresence;
    let operations: SecureCryptoOperations = SecureCryptoOperations::new(attestation);
    let mut storage: InMemoryStorage = InMemoryStorage::new();

    let service = U2F::new(&approval, &operations, &mut storage, logger.new(o!()))?;
    let future = U2FHID::bind_service(&handle, transport, service, logger.new(o!()));
    core.run(future)?;

    Ok(())
}

fn main() {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let logger = Logger::root(slog_term::FullFormat::new(plain).build().fuse(), o!());
    info!(logger, "SoftU2F started");
    run(logger).unwrap();
}
