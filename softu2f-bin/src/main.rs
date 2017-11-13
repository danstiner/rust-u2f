#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate slog;

extern crate futures;
extern crate libc;
extern crate rprompt;
extern crate sandbox_ipc;
extern crate serde_json;
extern crate serde;
extern crate slog_term;
extern crate softu2f_test_user_presence;
extern crate tokio_core;
extern crate tokio_io;
extern crate u2f_core;
extern crate u2fhid_protocol;
extern crate uhid_linux_tokio;
extern crate users;

mod user_file_storage;
mod user_presence;

use std::env;
use std::io;
use std::path::{Path, PathBuf};

use futures::{future, Future, Stream, Sink};
use slog::{Drain, Logger};
use tokio_core::reactor::Core;
use libc::{gid_t, uid_t};

use u2f_core::{SecureCryptoOperations, U2F};
use u2fhid_protocol::{Packet, U2FHID};
use uhid_linux_tokio::{Bus, CreateParams, UHIDDevice, InputEvent, OutputEvent, StreamError};
use user_file_storage::UserFileStorage;
use user_presence::NotificationUserPresence;

const DBUS_SESSION_BUS_ADDRESS_VAR: &str = "DBUS_SESSION_BUS_ADDRESS";

const DEFAULT_PROGAM_NAME: &str = "softu2f-bin";

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

#[derive(Clone, Copy)]
pub struct SecurityIds {
    pub gid: gid_t,
    pub uid: uid_t,
}

pub struct PreSudoEnvironment {
    dbus_session_bus_address: String,
    home: PathBuf,
    security_ids: SecurityIds,
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
        StreamError::UnknownEventType(_) => {
            io::Error::new(io::ErrorKind::Other, "Unknown event type")
        }
        StreamError::BufferOverflow(_, _) => {
            io::Error::new(io::ErrorKind::Other, "Buffer overflow")
        }
        StreamError::Nul(err) => io::Error::new(io::ErrorKind::Other, err),
        StreamError::Unknown => io::Error::new(io::ErrorKind::Other, "Unknown"),
    }
}

fn program_name() -> String {
    let path = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return String::from(DEFAULT_PROGAM_NAME),
    };
    let file_name = match path.file_name() {
        Some(file_name) => file_name,
        None => return String::from(DEFAULT_PROGAM_NAME),
    };
    file_name.to_str().unwrap_or(DEFAULT_PROGAM_NAME).to_owned()
}

fn pre_sudo_env() -> Option<PreSudoEnvironment> {
    fn try_pre_sudo_env() -> Result<PreSudoEnvironment, env::VarError> {
        let dbus_session_bus_address = env::var(DBUS_SESSION_BUS_ADDRESS_VAR)?;
        let home = PathBuf::from(env::var("HOME")?);
        let uid: String = env::var("SUDO_UID")?;
        let gid: String = env::var("SUDO_GID")?;
        let uid: uid_t = uid_t::from_str_radix(&uid, 10)
            .expect("Environment variable SUDO_UID must be a valid UID");
        let gid: gid_t = gid_t::from_str_radix(&gid, 10)
            .expect("Environment variable SUDO_GID must be a valid GID");
        Ok(PreSudoEnvironment {
            dbus_session_bus_address: dbus_session_bus_address,
            home: home,
            security_ids: SecurityIds {
                gid: gid,
                uid: uid,
            }
        })
    }

    match try_pre_sudo_env() {
        Ok(res) => Some(res),
        Err(_) => {
            eprintln!("Usage: sudo --preserve-env {}", program_name());
            None
        },
    }
}

fn run(logger: slog::Logger, pre_sudo_env: PreSudoEnvironment) -> io::Result<()> {
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

    let security_ids = pre_sudo_env.security_ids;
    let store_path = [&pre_sudo_env.home, Path::new(".softu2f-secrets.json")].iter().collect();

    let mut core = Core::new()?;
    let handle = core.handle();

    let uhid_device = UHIDDevice::create(&handle, create_params, logger.new(o!()))?;
    let transport = uhid_device
        .filter_map(output_to_packet)
        .with(packet_to_input)
        .map_err(stream_error_to_io_error)
        .sink_map_err(stream_error_to_io_error);

    let attestation = u2f_core::self_signed_attestation();
    let user_presence = Box::new(NotificationUserPresence::new(core.handle(), pre_sudo_env));
    let operations = Box::new(SecureCryptoOperations::new(attestation));
    let storage = Box::new(UserFileStorage::new(store_path, security_ids, logger.new(o!()))?);

    let service = U2F::new(user_presence, operations, storage, logger.new(o!()))?;
    let future = U2FHID::bind_service(&handle, transport, service, logger.new(o!()));
    core.run(future)?;

    Ok(())
}

fn main() {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let logger = Logger::root(slog_term::FullFormat::new(plain).build().fuse(), o!());

    let pre_sudo_env = match pre_sudo_env() {
        Some(res) => res,
        None => return,
    };

    debug!(logger, "SoftU2F started");
    run(logger, pre_sudo_env).unwrap();
}
