extern crate futures;
extern crate rprompt;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate tokio_core;
extern crate tokio_service;
extern crate u2f_core;

use std::ascii::AsciiExt;
use std::io;

use futures::{future, Future, Stream, Sink};
use slog::*;
use tokio_core::reactor::Core;
use tokio_service::{Service, NewService};

use u2f_core::{ApplicationParameter, ApprovalService, InMemoryStorage, SecureCryptoOperations, U2F};

struct CommandPromptApprovalService;

impl CommandPromptApprovalService {
    fn approve(prompt: &str) -> io::Result<bool> {
        loop {
            let reply = rprompt::prompt_reply_stdout(prompt)?;
            if reply.eq_ignore_ascii_case("y") {
                return Ok(true)
            } else if reply.eq_ignore_ascii_case("n") {
                return Ok(false)
            }
        }
    }
}

impl ApprovalService for CommandPromptApprovalService {
    fn approve_registration(&self, application: &ApplicationParameter) -> io::Result<bool> {
        Self::approve("Approve registration [y/n]: ")
    }

    fn approve_authentication(&self, application: &ApplicationParameter) -> io::Result<bool> {
        Self::approve("Approve authentication [y/n]: ")
    }
}

struct U2FUHIDDevice;

impl U2FUHIDDevice {
    fn new(handle) -> Result<U2FUHIDDevice, ()> {
        Ok(U2FUHIDDevice)
    }
}

fn run() -> io::Result<()> {
    let mut core = Core::new()?;
    let handle = core.handle();

    let mut u2f_uhid_device = U2FUHIDDevice::create(&handle)?;
    let uhid = ();
    let u2f_connection = uhid.framed_u2fhid();

    let (writer, reader) = u2f_connection.split();
    let attestation = u2f_core::self_signed_attestation();
    let approval = CommandPromptApprovalService;
    let operations: SecureCryptoOperations = SecureCryptoOperations::new(attestation);
    let storage: InMemoryStorage = InMemoryStorage::new();
    let service = U2F::new(&approval, &operations, &mut storage)?;

    let response = reader.and_then(move |req| service.call(req));
    let server = writer.send(response)
        .then(|_| Ok(()));
    handle.spawn(server);

    Ok(())
}

fn main() {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let logger = Logger::root(
        slog_term::FullFormat::new(plain)
        .build().fuse(), o!()
    );
    info!(logger, "SoftU2F started");
    run().unwrap();
}
