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
use futures::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::net::{unix::UCred, UnixStream};
use tokio_serde::formats::Bincode;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info};
use tracing_subscriber::prelude::*;

use softu2f_system_daemon::{
    CreateDeviceError, CreateDeviceRequest, DeviceDescription, SocketInput, SocketOutput,
};
use u2f_core::{OpenSSLCryptoOperations, Request, Response, SecretStore, Service, U2fService};
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
    CreateDeviceError(#[from] CreateDeviceError),

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
struct VirtualU2fDevice {
    u2f_service: U2fService<Box<dyn SecretStore>, OpenSSLCryptoOperations, NotificationUserPresence>,
    system_socket: SocketTransport,
    uhid_device: DeviceDescription,
}

impl VirtualU2fDevice {
    pub async fn create(system_daemon_socket: &Path) -> Result<Self, Error> {
        let config = config::Config::load()?;
        let user_presence = NotificationUserPresence::new();
        let attestation = u2f_core::self_signed_attestation();
        let crypto = OpenSSLCryptoOperations::new(attestation);
        let secrets = secret_store::build(&config)?;

        let u2f_service = U2fService::new(secrets, crypto, user_presence);

        let stream = UnixStream::connect(system_daemon_socket)
            .await
            .map_err(|error| Error::Connect {
                error,
                socket_path: system_daemon_socket.to_owned(),
            })?;

        require_root(stream.peer_cred()?)?;

        let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());
        let mut system_socket: SocketTransport =
            tokio_serde::Framed::new(length_delimited, Bincode::default());

        let uhid_device = create_uhid_device(&mut system_socket).await?;

        Ok(Self {
            u2f_service,
            system_socket,
            uhid_device,
        })
    }

    pub async fn run_loop(mut self) -> Result<(), Error> {
        // todo check poll ready
        while let Some(request) = self.system_socket.next().await {
            let request: Request = todo!();
            let response = self.u2f_service.call(request).await?;
            self.system_socket.send(todo!());
        }
        todo!()
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

type SocketTransport = tokio_serde::Framed<
    Framed<UnixStream, LengthDelimitedCodec>,
    SocketOutput,
    SocketInput,
    Bincode<SocketOutput, SocketInput>,
>;

async fn create_uhid_device(
    system_socket: &mut SocketTransport,
) -> Result<DeviceDescription, Error> {
    debug!("Sending create device request");
    system_socket
        .send(SocketInput::CreateDeviceRequest(CreateDeviceRequest))
        .await?;

    while let Some(output) = system_socket.next().await {
        match output? {
            SocketOutput::CreateDeviceResponse(Ok(device)) => return Ok(device),
            SocketOutput::CreateDeviceResponse(Err(err)) => return Err(err.into()),
            SocketOutput::Report(_) => {
                return Err(Error::InvalidState(
                    "Received HID report while waiting for create device response",
                ))
            }
        }
    }

    Err(Error::InvalidState(
        "Socket closed while waiting for response to create device request",
    ))
}
