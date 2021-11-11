extern crate clap;
extern crate futures;
extern crate hostname;
extern crate libc;
extern crate libsystemd;
extern crate nanoid;
extern crate take_mut;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_linux_uhid;
extern crate tower;
// extern crate u2fhid_protocol;
// extern crate users;

use std::io;
use std::os::unix::net;
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::IntoRawFd;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use crate::socket_server::SocketServer;
use clap::{App, Arg};
use futures::future;
use futures::Future;
use libsystemd::activation::IsType;
use thiserror::Error;
use tokio::net::unix::SocketAddr;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tower::Service;
use tracing::{error, info};
use tracing_subscriber::prelude::*;

mod device;
mod socket_server;

const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const PATH_ARG: &str = "path";

#[derive(Debug, Error)]
enum Error {
    // #[error("Device error")]
    // Device(#[from] device::Error),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Systemd(#[from] libsystemd::errors::SdError),

    #[error("Wrong socket, expected a stream type socket")]
    WrongSocket,

    #[error("Expected one socket from systemd, instead got {count}")]
    WrongListenFdCount { count: usize },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = App::new("Rust-u2f System Daemon")
        .version(VERSION)
        .author(AUTHORS)
        .about(DESCRIPTION)
        .arg(Arg::with_name(PATH_ARG)
            .short("s")
            .long("socket")
            .takes_value(true)
            .help("Bind to specified socket path instead of file-descriptor from systemd"))
        .after_help("By default expects to be run via systemd as root and passed a socket file-descriptor to listen on.")
        .get_matches();

    let socket_path = args.value_of(PATH_ARG);

    if libsystemd::logging::connected_to_journal() {
        tracing_subscriber::registry()
            .with(tracing_journald::layer().expect("Unable to connect to journald socket"))
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }

    info!(version = VERSION, "Starting rust-u2f system daemon");

    if let Err(ref err) = run(socket_path).await {
        error!(error = ?err, "Error encountered, exiting");
    }
}

async fn run(socket_path: Option<&str>) -> Result<(), Error> {
    let socket = socket_listener(socket_path)?;
    let handler = ConnectionHandler::new();

    SocketServer::serve(socket, handler).await
}

fn socket_listener(socket_path: Option<&str>) -> Result<UnixListener, Error> {
    if let Some(socket_path) = socket_path {
        UnixListener::bind(socket_path).map_err(Error::Io)
    } else {
        systemd_socket_listener()
    }
}

fn systemd_socket_listener() -> Result<UnixListener, Error> {
    let descriptors = libsystemd::activation::receive_descriptors(true)?;

    if descriptors.len() != 1 {
        return Err(Error::WrongListenFdCount {
            count: descriptors.len(),
        });
    }

    let descriptor = descriptors.into_iter().next().unwrap();

    if !descriptor.is_unix() {
        return Err(Error::WrongSocket);
    }

    let listener = unsafe { net::UnixListener::from_raw_fd(descriptor.into_raw_fd()) };

    UnixListener::from_std(listener).map_err(Error::Io)
}

#[derive(Debug)]
struct ConnectionHandler {}

impl ConnectionHandler {
    fn new() -> Self {
        ConnectionHandler {}
    }
}

impl Service<(UnixStream, SocketAddr)> for ConnectionHandler {
    type Response = Connection;
    type Error = Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (_stream, _addr): (UnixStream, SocketAddr)) -> Self::Future {
        // TODO wrap raw unix stream with a client struct that creates the device when asked to

        //     debug!(log, "accepting connection";
        //         "local_addr" => ?stream.local_addr(),
        //         "peer_addr" => ?stream.peer_addr(),
        //         "peer_cred" => ?stream.peer_cred());

        // DeviceService::new(stream, ())
        Box::pin(future::ok(todo!()))
    }
}

#[must_use = "futures do nothing unless polled"]
#[derive(Debug)]
struct Connection {}

impl Connection {
    fn new(stream: UnixStream, addr: SocketAddr) -> Self {
        Connection {}
    }
}

impl Future for Connection
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Maybe replace with BidirectionalPipe connecting UnixStream from user daemon and uhid device transport
        // But only once the create request has been received and device created
        todo!()
    }
}
