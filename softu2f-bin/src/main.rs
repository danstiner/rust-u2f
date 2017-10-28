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
use std::io::{self, Write};
use std::rc::Rc;

use futures::stream::FilterMap;
use futures::sink::With;
use futures::{future, Future, Stream, Sink, Poll, StartSend, BoxFuture};
use slog::*;
use tokio_core::reactor::Core;
use tokio_io::AsyncRead;

use u2f_core::{ApplicationParameter, UserPresence, InMemoryStorage, SecureCryptoOperations, U2F,
               ResponseError, Service};
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
    fn approve_registration(&self, application: &ApplicationParameter) -> io::Result<bool> {
        Self::approve("Approve registration [y/n]: ")
    }

    fn approve_authentication(&self, application: &ApplicationParameter) -> io::Result<bool> {
        Self::approve("Approve authentication [y/n]: ")
    }
}

fn output_to_packet(output_event: OutputEvent) -> Option<Packet> {
    match output_event {
        OutputEvent::Output { data } => Some(Packet::from_bytes(&data).unwrap()),
        _ => None,
    }
}

fn packet_to_input(packet: Packet) -> BoxFuture<InputEvent, StreamError> {
    future::ok(InputEvent::Input { data: packet.into_bytes() }).boxed()
}

struct ServiceErrorMap<S: Service, F> {
    inner: S,
    map_err_fn: Rc<F>,
}

impl<S, F, U> ServiceErrorMap<S, F>
where
    S: Service,
    F: Fn(S::Error) -> U,
{
    fn new(inner: S, f: F) -> ServiceErrorMap<S, F> {
        ServiceErrorMap {
            inner: inner,
            map_err_fn: Rc::new(f),
        }
    }
}

fn map_service_error<S, F, U>(inner: S, f: F) -> ServiceErrorMap<S, F> 
where
    S: Service,
    F: Fn(S::Error) -> U,{
    ServiceErrorMap::new(inner, f)
}

impl<S, F, U> Service for ServiceErrorMap<S, F>
where
    S: Service,
    S::Future: Sized,
    <S as u2f_core::Service>::Future: 'static,
    F: Fn(S::Error) -> U + 'static,
{
    type Request = S::Request;
    type Response = S::Response;
    type Error = U;
    type Future = Box<Future<Item=S::Response, Error=U>>;

    fn call(&mut self, req: Self::Request) -> Self::Future {
        let f = Rc::clone(&self.map_err_fn);
        Box::new(self.inner.call(req).map_err(move |err| (*f)(err)))
    }
}

fn response_error_to_stream_error(err: ResponseError) -> StreamError {
    match err {
        ResponseError::Io(err) => StreamError::Io(err),
        ResponseError::Signing(_) => StreamError::Unknown,
    }
}

const InputReportLen: u8 = 64;
const OutputReportLen: u8 = 64;

// HID Report Descriptor from http://www.usb.org/developers/hidpage/HUTRR48.pdf
const ReportDescriptor: [u8; 34] = [
        0x06, 0xd0, 0xf1,             // USAGE_PAGE (FIDO Alliance)
        0x09, 0x01,                   // USAGE (Keyboard)
        0xa1, 0x01,                   // COLLECTION (Application)
        0x09, 0x20,                   //   USAGE (Input Report Data)
        0x15, 0x00,                   //   LOGICAL_MINIMUM (0)
        0x26, 0xff, 0x00,             //   LOGICAL_MAXIMUM (255)
        0x75, 0x08,                   //   REPORT_SIZE (8)
        0x95, InputReportLen,         //   REPORT_COUNT (64)
        0x81, 0x02,                   //   INPUT (Data,Var,Abs)
        0x09, 0x21,                   //   USAGE(Output Report Data)
        0x15, 0x00,                   //   LOGICAL_MINIMUM (0)
        0x26, 0xff, 0x00,             //   LOGICAL_MAXIMUM (255)
        0x75, 0x08,                   //   REPORT_SIZE (8)
        0x95, OutputReportLen,        //   REPORT_COUNT (64)
        0x91, 0x02,                   //   OUTPUT (Data,Var,Abs)
        0xc0,                         // END_COLLECTION
];

fn run() -> io::Result<()> {
    let create_params = CreateParams {
        name: String::from("SoftU2F-Linux"),
        phys: String::from(""),
        uniq: String::from(""),
        bus: Bus::USB,
        vendor: 0xffff,
        product: 0xffff,
        version: 0,
        country: 0,
        data: ReportDescriptor.to_vec(),
    };

    let mut core = Core::new()?;
    let handle = core.handle();

    let uhid_device = UHIDDevice::create(&handle, create_params)?;
    let transport = uhid_device.filter_map(output_to_packet).with(
        packet_to_input,
    );

    let attestation = u2f_core::self_signed_attestation();
    let approval = CommandPromptUserPresence;
    let operations: SecureCryptoOperations = SecureCryptoOperations::new(attestation);
    let mut storage: InMemoryStorage = InMemoryStorage::new();
    let service = U2F::new(&approval, &operations, &mut storage)?;
    let service = map_service_error(service, response_error_to_stream_error);

    let future = U2FHID::bind_service(&handle, transport, service);

    core.run(future).unwrap();
    Ok(())
}

fn main() {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let logger = Logger::root(slog_term::FullFormat::new(plain).build().fuse(), o!());
    info!(logger, "SoftU2F started");
    run().unwrap();
}
