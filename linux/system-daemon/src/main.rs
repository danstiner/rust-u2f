extern crate clap;
extern crate futures;
extern crate hostname;
extern crate libc;
extern crate libsystemd;
extern crate nanoid;
extern crate take_mut;
extern crate tokio;
extern crate tokio_linux_uhid;
extern crate tokio_util;
extern crate tower;
extern crate users;

use std::io;
use std::os::unix::net;
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::IntoRawFd;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use crate::socket_server::SocketServer;
use clap::{Arg, Command};
use futures::future;
use futures::future::Ready;
use futures::Future;
use libsystemd::activation::IsType;
use thiserror::Error;
use tokio::net::unix::SocketAddr;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio_linux_uhid::StreamError;
use tower::Service;
use tracing::{error, info, trace};
use tracing_subscriber::prelude::*;

mod connection;
mod socket_server;

const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const SOCKET_PATH_ARG: &str = "socket_path";

#[derive(Debug, Error)]
enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Systemd(#[from] libsystemd::errors::SdError),

    #[error("Wrong socket, expected a stream type socket")]
    WrongSocket,

    #[error("Expected one socket from systemd, instead got {count}")]
    WrongListenFdCount { count: usize },
}

#[tokio::main]
async fn main() {
    let args = Command::new("Rust-Fido System Daemon")
        .version(VERSION)
        .author(AUTHORS)
        .about(DESCRIPTION)
        .arg(Arg::new(SOCKET_PATH_ARG)
            .short('s')
            .long("socket")
            .num_args(1)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .help("Bind to specified socket path instead of expecting a file descriptor from systemd"))
        .get_matches();

    let socket_path = args.get_one::<String>(SOCKET_PATH_ARG);

    if libsystemd::logging::connected_to_journal() {
        tracing_subscriber::registry()
            .with(tracing_journald::layer().expect("Unable to connect to journald socket"))
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }

    info!(version = VERSION, "Starting rust-fido system daemon");

    if let Err(ref err) = run(socket_path.map(|x| &**x)).await {
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
    type Response = Pin<Box<dyn Future<Output = Result<(), StreamError>> + Send>>;
    type Error = Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (stream, addr): (UnixStream, SocketAddr)) -> Self::Future {
        trace!("ConnectionHandler::call");
        future::ok(Box::pin(connection::handle(stream, addr)))
    }
}
