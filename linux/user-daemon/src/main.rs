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
extern crate pin_project;
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

use clap::{Arg, Command};
use futures::{ready, Sink, SinkExt, Stream, StreamExt};
use pin_project::pin_project;
use thiserror::Error;
use tokio::net::UnixStream;
use tokio_serde::formats::Bincode;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;

use softu2f_system_daemon::{
    CreateDeviceError, CreateDeviceRequest, DeviceDescription, Report, SocketInput, SocketOutput,
};
use u2f_core::{OpenSSLCryptoOperations, U2fService};
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

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let args = Command::new("Rust-U2F User Daemon")
        .version(VERSION)
        .author(AUTHORS)
        .about(DESCRIPTION)
        .arg(Arg::new(SOCKET_PATH_ARG)
            .short('s')
            .long("socket")
            .default_value(softu2f_system_daemon::DEFAULT_SOCKET_PATH)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .action(clap::ArgAction::Set)
            .help("Bind to specified socket path instead of file-descriptor from systemd"))
        .after_help("By default expects to be run via systemd as root and passed a socket file-descriptor to listen on.")
        .get_matches();

    let socket_path = match args.get_one::<String>(SOCKET_PATH_ARG) {
        Some(path) => Path::new(path),
        None => {
            error!("No socket path provided in arguments");
            return;
        }
    };

    if libsystemd::logging::connected_to_journal() {
        match tracing_journald::layer() {
            Ok(layer) => {
                tracing_subscriber::registry().with(layer).init();
            }
            Err(e) => {
                error!("Unable to connect to journald socket: {}", e);
                tracing_subscriber::fmt::init();
            }
        }
    } else {
        tracing_subscriber::fmt::init();
    }

    info!(version = VERSION, "Starting rust-u2f user daemon");

    if let Err(ref err) = run(socket_path).await {
        error!("Error encountered, exiting: {}", err);
    }
}

async fn run(socket_path: &Path) -> Result<(), Error> {
    let config = config::Config::load()?;
    let user_presence = NotificationUserPresence::new();
    let attestation = u2f_core::self_signed_attestation();
    let crypto = OpenSSLCryptoOperations::new(attestation);
    let secrets = secret_store::build(&config)?;

    let u2f_service = U2fService::new(secrets, crypto, user_presence);

    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|error| Error::Connect {
            error,
            socket_path: socket_path.to_owned(),
        })?;

    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());
    let mut system_socket: SocketTransport =
        tokio_serde::Framed::new(length_delimited, Bincode::default());

    let uhid_device = create_uhid_device(&mut system_socket).await?;
    debug!("UHID device created with id: {}", uhid_device.id);

    U2fHidServer::new(Pipe::new(system_socket, SocketToHid), u2f_service).await
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

    match system_socket.next().await {
        Some(Ok(SocketOutput::CreateDeviceResponse(Ok(device)))) => Ok(device),
        Some(Ok(SocketOutput::CreateDeviceResponse(Err(err)))) => Err(err.into()),
        Some(Ok(SocketOutput::Report(_))) => Err(Error::InvalidState(
            "Received HID report while waiting for create device response",
        )),
        Some(Err(err)) => Err(err.into()),
        None => Err(Error::InvalidState(
            "Socket closed while waiting for response to create device request",
        )),
    }
}

struct SocketToHid;

impl Proxy for SocketToHid {
    type StreamInput = Result<SocketOutput, Self::Error>;
    type StreamOutput = Packet;
    type SinkInput = Packet;
    type SinkOutput = SocketInput;
    type Error = io::Error;

    fn try_map_stream(
        &mut self,
        input: Self::StreamInput,
    ) -> Result<Option<Self::StreamOutput>, Self::Error> {
        match input {
            Ok(SocketOutput::Report(report)) => Packet::from_bytes(report.as_bytes())
                .map(Option::Some)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "TODO")),
            Ok(SocketOutput::CreateDeviceResponse(_)) => {
                warn!("Received unexpected CreateDeviceResponse");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    fn try_map_sink(
        &mut self,
        input: Self::SinkInput,
    ) -> Result<Option<Self::SinkOutput>, Self::Error> {
        Ok(Some(SocketInput::Report(Report::new(input.to_bytes()))))
    }
}

pub trait Proxy {
    type StreamInput;
    type StreamOutput;
    type SinkInput;
    type SinkOutput;
    type Error;

    fn try_map_stream(
        &mut self,
        input: Self::StreamInput,
    ) -> Result<Option<Self::StreamOutput>, Self::Error>;
    fn try_map_sink(
        &mut self,
        input: Self::SinkInput,
    ) -> Result<Option<Self::SinkOutput>, Self::Error>;
}

#[pin_project]
pub struct Pipe<T, P> {
    proxy: P,
    #[pin]
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
    T: Stream<Item = P::StreamInput> + Unpin,
{
    type Item = Result<P::StreamOutput, P::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        while let Some(input) = ready!(Pin::new(&mut this.inner).poll_next(cx)) {
            match this.proxy.try_map_stream(input) {
                Ok(Some(item)) => return Poll::Ready(Some(Ok(item))),
                Ok(None) => continue, // Item mapped to None, skip returning it
                Err(err) => return Poll::Ready(Some(Err(err))),
            };
        }

        Poll::Ready(None)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<T, P> Sink<P::SinkInput> for Pipe<T, P>
where
    P: Proxy,
    T: Sink<P::SinkOutput, Error = P::Error> + Unpin,
{
    type Error = T::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: P::SinkInput) -> Result<(), Self::Error> {
        match self.proxy.try_map_sink(item) {
            Ok(Some(item)) => self.inner.start_send_unpin(item),
            Ok(None) => Ok(()), // Item mapped to None, skip send
            Err(err) => Err(err),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}
