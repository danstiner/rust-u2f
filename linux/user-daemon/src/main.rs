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
use u2f_core::{OpenSSLCryptoOperations, Request, Response, SecretStore, Service, U2fService};
use u2fhid_protocol::{Decoder, Encoder, Packet, U2fHidProtocol};
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
    u2f_service:
        U2fService<Box<dyn SecretStore>, OpenSSLCryptoOperations, NotificationUserPresence>,
    u2f_transport: U2fTransport,
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

        let protocol = Compose::new(U2fHidProtocol::new(), PacketCodec);

        let u2f_transport: U2fTransport = u2fhid_protocol::Framed::new(system_socket, protocol);

        Ok(Self {
            u2f_service,
            u2f_transport,
            uhid_device,
        })
    }

    pub async fn run_loop(mut self) -> Result<(), Error> {
        // todo check poll ready
        while let Some(request) = self.u2f_transport.next().await {
            let response = self.u2f_service.call(request?).await?;
            self.u2f_transport.send(response).await?;
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

type U2fTransport = u2fhid_protocol::Framed<SocketTransport, Compose<U2fHidProtocol, PacketCodec>>;

pub struct Compose<Outer, Inner> {
    outer: Outer,
    inner: Inner,
}

impl<Outer, Inner> Compose<Outer, Inner> {
    pub fn new(outer: Outer, inner: Inner) -> Self {
        Self { outer, inner }
    }
}

impl<Outer, Inner, I, E> Decoder for Compose<Outer, Inner>
where
    Outer: Decoder<Item = I, Error = E>,
    Inner: Decoder<Decoded = I, Error = E>,
{
    type Item = Inner::Item;
    type Decoded = Outer::Decoded;
    type Error = E;

    fn decode(&mut self, item: &mut Self::Item) -> Result<Option<Self::Decoded>, Self::Error> {
        match self.inner.decode(item) {
            Ok(Some(mut item)) => self.outer.decode(&mut item),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl<Outer, Inner, I, E> Encoder for Compose<Outer, Inner>
where
    Outer: Encoder<Encoded = I, Error = E>,
    Inner: Encoder<Item = I, Error = E>,
{
    type Item = Outer::Item;
    type Encoded = Inner::Encoded;
    type Error = E;

    fn encode(&mut self, item: &mut Self::Item) -> Result<Option<Self::Encoded>, Self::Error> {
        match self.outer.encode(item) {
            Ok(Some(mut item)) => self.inner.encode(&mut item),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

pub struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = SocketOutput;
    type Decoded = Packet;
    type Error = io::Error;

    fn decode(&mut self, item: &mut Self::Item) -> Result<Option<Self::Decoded>, Self::Error> {
        match item {
            SocketOutput::Report(report) => Packet::from_bytes(report.as_bytes())
                .map(Option::Some)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "TODO")),
            _ => Ok(None),
        }
    }
}

impl Encoder for PacketCodec {
    type Item = Packet;
    type Encoded = SocketInput;
    type Error = io::Error;

    fn encode(&mut self, item: &mut Self::Item) -> Result<Option<Self::Encoded>, Self::Error> {
        Ok(Some(SocketInput::Report(Report::new(item.to_bytes()))))
    }
}

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

// // #[pin_project]
// pub struct BidirectionalMap<T, I, O> {
//     // #[pin]
//     transport: T,
//     i: I,
//     o: O,
// }

// impl<T, I, O> BidirectionalMap<T, I, O>
// where
//     T: Stream,
// {
//     pub fn new(transport: T, i: I, o: O) -> Self {
//         Self { transport, i, o }
//     }
// }

// impl<T, I, O> Stream for BidirectionalMap<T, I, O>
// where
//     T: Stream,
//     I: FnMut(T::Item),
// {
//     type Item = I::Output;

//     fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         todo!()
//     }
// }

// impl<T, I, O, E, I2> Sink<I2> for BidirectionalMap<T, I, O>
// where
//     T: Sink<O::Output, Error = E>,
//     O: FnMut(I2),
// {
//     type Error = E;

//     fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         todo!()
//     }

//     fn start_send(self: Pin<&mut Self>, item: I2) -> Result<(), Self::Error> {
//         todo!()
//     }

//     fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         todo!()
//     }

//     fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         todo!()
//     }
// }
