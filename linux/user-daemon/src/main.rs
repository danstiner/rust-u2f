extern crate alloc;
extern crate bincode;
extern crate clap;
extern crate core;
extern crate directories;
extern crate dirs;
extern crate futures;
extern crate futures_cpupool;
extern crate lazy_static;
extern crate notify_rust;
extern crate secret_service;
extern crate serde_derive;
extern crate serde_json;
extern crate softu2f_system_daemon;
extern crate thiserror;
extern crate tokio;
extern crate tracing;
extern crate tracing_subscriber;
extern crate u2f_core;
// extern crate u2fhid_protocol;

use std::{
    io,
    path::{Path, PathBuf},
};

use clap::{App, Arg};
use thiserror::Error;
use tokio::net::{unix::UCred, UnixStream};
use tracing::{debug, error, info};
use tracing_subscriber::prelude::*;

use softu2f_system_daemon::{CreateDeviceError, CreateDeviceRequest, DeviceDescription};
use u2f_core::{OpenSSLCryptoOperations, U2F};
use user_presence::NotificationUserPresence;

mod atomic_file;
mod config;
mod secret_store;
mod user_presence;

const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const SOCKET_PATH_ARG: &str = "socket_path";

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unable to connect to socket {socket_path}, I/O error: {error}")]
    Connect {
        error: io::Error,
        socket_path: PathBuf,
    },

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Bincode error: {0}")]
    Bincode(bincode::ErrorKind),

    #[error("{0}")]
    InvalidState(&'static str),

    #[error("{0}")]
    DeviceCreateFailed(#[from] CreateDeviceError),

    #[error("Home directory path could not be retrieved from the operating system")]
    HomeDirectoryNotFound,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = App::new("SoftU2F User Daemon")
        .version(VERSION)
        .author(AUTHORS)
        .about(DESCRIPTION)
        .arg(Arg::with_name(SOCKET_PATH_ARG)
            .short("s")
            .long("socket")
            .takes_value(true)
            .help("Bind to specified socket path instead of file-descriptor from systemd"))
        .after_help("By default expects to be run via systemd as root and passed a socket file-descriptor to listen on.")
        .get_matches();

    let system_daemon_socket = Path::new(
        args.value_of(SOCKET_PATH_ARG)
            .unwrap_or(softu2f_system_daemon::DEFAULT_SOCKET_PATH),
    );

    if libsystemd::logging::connected_to_journal() {
        tracing_subscriber::registry()
            .with(tracing_journald::layer().expect("Unable to connect to journald socket"))
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }

    info!(version = VERSION, "Starting rust-u2f user daemon");

    if let Err(ref err) = run(system_daemon_socket).await {
        error!(error = ?err, "Error encountered, exiting");
    }
}

async fn run(system_daemon_socket: &Path) -> Result<(), Error> {
    let u2f = VirtualU2fDevice::create(system_daemon_socket).await?;
    u2f.run_loop().await
}

#[must_use]
struct VirtualU2fDevice {}

impl VirtualU2fDevice {
    pub async fn create(system_daemon_socket: &Path) -> Result<Self, Error> {
        let config = config::Config::load()?;
        let user_presence = NotificationUserPresence::new();
        let attestation = u2f_core::self_signed_attestation();
        let crypto = OpenSSLCryptoOperations::new(attestation);
        let secrets = secret_store::build(&config)?;

        let _u2f = U2F::new(user_presence, crypto, secrets);

        let system_daemon_socket =
            UnixStream::connect(system_daemon_socket)
                .await
                .map_err(|error| Error::Connect {
                    error,
                    socket_path: system_daemon_socket.to_owned(),
                })?;

        require_root(system_daemon_socket.peer_cred()?)?;

        let _uhid_device = create_uhid_device().await?;

        todo!()
    }

    pub async fn run_loop(self) -> Result<(), Error> {
        loop {
            todo!()
        }
    }
}

fn require_root(peer: UCred) -> Result<(), Error> {
    if peer.uid() != 0 {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Expected socket peer to be running as root user",
        )
        .into())
    } else {
        Ok(())
    }
}

// fn connected(
//     stream: UnixStream,
//     handle: Handle,
//     logger: Logger,
// ) -> Box<dyn Future<Item = (), Error = ProgramError>> {
//     match stream
//         .peer_cred()
//         .map_err(ProgramError::Io)
//         .and_then(require_root)
//     {
//         Ok(()) => (),
//         Err(err) => return Box::new(future::err(err)),
//     };

//     let transport = bind_transport(stream);
//     let created_device = create_device(transport, logger.clone());

//     Box::new(created_device.and_then(move |(device, transport)| {
//         bind_service(device, transport, handle, &logger.clone())
//     }))
// }

// fn bind_transport(stream: UnixStream) -> Transport {
//     let framed_write = length_delimited::FramedWrite::new(stream);
//     let framed_readwrite = length_delimited::FramedRead::new(framed_write);
//     let mapped_err = framed_readwrite.sink_from_err().from_err();
//     let bincode_read = ReadBincode::new(mapped_err);
//     let bincode_readwrite = WriteBincode::<_, SocketInput>::new(bincode_read);
//     Box::new(bincode_readwrite)
// }

async fn create_uhid_device() -> Result<DeviceDescription, Error> {
    let request = CreateDeviceRequest;
    debug!(?request, "Sending create device request");
    todo!()
    // let send = transport.send(SocketInput::CreateDeviceRequest(request));
    // let created = send.and_then(move |transport| {
    //     transport
    //         .into_future()
    //         .and_then(|(output, transport)| {
    //             let res = match output {
    //                 Some(SocketOutput::CreateDeviceResponse(Ok(device))) => {
    //                     future::ok((device, transport))
    //                 }
    //                 Some(SocketOutput::CreateDeviceResponse(Err(err))) => {
    //                     future::err((ProgramError::DeviceCreateFailed(err), transport))
    //                 }
    //                 Some(_) => future::err((
    //                     ProgramError::InvalidState("Expected create device response"),
    //                     transport,
    //                 )),
    //                 None => future::err((
    //                     ProgramError::Io(io::Error::new(
    //                         io::ErrorKind::ConnectionAborted,
    //                         "Socket transport closed unexpectedly",
    //                     )),
    //                     transport,
    //                 )),
    //             };
    //             res
    //         })
    //         .or_else(move |(err, mut transport)| {
    //             transport
    //                 .close()
    //                 .into_future()
    //                 .map_err(
    //                     move |err| error!(logger, "failed to close transport"; "error" => ?err),
    //                 )
    //                 .then(|_| future::err(err))
    //         })
    // });
}

// fn bind_service<T>(
//     device: DeviceDescription,
//     transport: T,
//     handle: Handle,
//     log: &Logger,
// ) -> Box<dyn Future<Item = (), Error = ProgramError>>
// where
//     T: Sink<SinkItem = SocketInput, SinkError = ProgramError>
//         + Stream<Item = SocketOutput, Error = ProgramError>
//         + 'static,
// {
//     info!(log, "Virtual U2F device created"; "device_id" => device.id);

//     let packet_logger = log.new(o!());
//     let transport = transport
//         .filter_map(move |output| socket_output_to_packet(&packet_logger, output))
//         .with(|packet| future::ok(packet_to_socket_input(packet)));

//     let attestation = u2f_core::self_signed_attestation();
//     let user_presence = Box::new(NotificationUserPresence::new(&handle, log.new(o!())));
//     let operations = Box::new(SecureCryptoOperations::new(attestation));
//     let storage = match build_storage(log) {
//         Ok(store) => store,
//         Err(err) => return Box::new(future::err(err)),
//     };
//     let service = match U2F::new(user_presence, operations, storage, log.new(o!())) {
//         Ok(service) => service,
//         Err(err) => return Box::new(future::err(ProgramError::Io(err))),
//     };

//     info!(log, "Ready to authenticate");

//     Box::new(U2FHID::bind_service(
//         handle,
//         transport,
//         service,
//         log.new(o!()),
//     ))
// }

// fn socket_output_to_packet(logger: &Logger, event: SocketOutput) -> Option<Packet> {
//     match event {
//         SocketOutput::Packet(raw_packet) => match Packet::from_bytes(&raw_packet.to_bytes()) {
//             Ok(packet) => Some(packet),
//             Err(error) => {
//                 info!(logger, "Bad packet"; "parse_error" => error);
//                 trace!(logger, "Packet"; "raw_packet" => raw_packet);
//                 None
//             }
//         },
//         _ => None,
//     }
// }

// fn packet_to_socket_input(packet: Packet) -> SocketInput {
//     SocketInput::Packet(softu2f_system_daemon::Packet::from_bytes(
//         &packet.into_bytes(),
//     ))
// }
