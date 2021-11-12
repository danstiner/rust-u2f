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
extern crate u2fhid_protocol;

use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};

use clap::{App, Arg};
use futures::{Sink, SinkExt, Stream, StreamExt};
use thiserror::Error;
use tokio::net::{unix::UCred, UnixStream};
use tokio_serde::formats::Bincode;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info};
use tracing_subscriber::prelude::*;

use softu2f_system_daemon::{
    CreateDeviceError, CreateDeviceRequest, DeviceDescription, Report, SocketInput, SocketOutput,
};
use u2f_core::{OpenSSLCryptoOperations, SecretStore, Service, U2fService};
use u2fhid_protocol::{Packet, U2fHidServer};
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

    let hid_transport: HidTransport = Pipe::new(system_socket, SocketToHid);

    U2fHidServer::new(hid_transport, u2f_service)
        .serve::<Error>()
        .await
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

type HidTransport = Pipe<SocketTransport, SocketToHid>;

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

struct SocketToHid;

impl Proxy for SocketToHid {
    type StreamInput = Result<SocketOutput, Self::Error>;
    type StreamOutput = Packet;
    type SinkInput = Packet;
    type SinkOutput = SocketInput;
    type Error = io::Error;

    fn map_stream(input: Self::StreamInput) -> Result<Option<Self::StreamOutput>, Self::Error> {
        match input {
            Ok(SocketOutput::Report(report)) => Packet::from_bytes(report.as_bytes())
                .map(Option::Some)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "TODO")),
            Ok(SocketOutput::CreateDeviceResponse(_)) => Ok(None), // todo log
            Err(err) => Err(err),
        }
    }

    fn map_sink(input: Self::SinkInput) -> Result<Option<Self::SinkOutput>, Self::Error> {
        Ok(Some(SocketInput::Report(Report::new(input.to_bytes()))))
    }
}

pub trait Proxy {
    type StreamInput;
    type StreamOutput;
    type SinkInput;
    type SinkOutput;
    type Error;

    fn map_stream(input: Self::StreamInput) -> Result<Option<Self::StreamOutput>, Self::Error>;
    fn map_sink(input: Self::SinkInput) -> Result<Option<Self::SinkOutput>, Self::Error>;
}

pub struct Pipe<T, P> {
    proxy: P,
    inner: T,
}

impl<T, P> Pipe<T, P>
where
    P: Proxy,
    T: Stream<Item = P::StreamInput> + Sink<P::SinkOutput>,
{
    pub fn new(inner: T, proxy: P) -> Self {
        Self { inner, proxy }
    }
}

impl<T, P> Stream for Pipe<T, P>
where
    P: Proxy,
    T: Stream<Item = P::StreamInput>,
{
    type Item = Result<P::StreamOutput, P::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // self.inner
        todo!()
    }
}

impl<T, P> Sink<P::SinkInput> for Pipe<T, P>
where
    P: Proxy,
    T: Sink<P::SinkOutput>,
{
    type Error = P::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn start_send(self: Pin<&mut Self>, item: P::SinkInput) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
    }
}
