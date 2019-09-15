extern crate clap;
extern crate futures;
extern crate hostname;
extern crate libc;
extern crate nanoid;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate slog;
extern crate slog_journald;
extern crate slog_term;
extern crate softu2f_system_daemon;
extern crate systemd;
extern crate take_mut;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_linux_uhid;
extern crate tokio_serde_bincode;
extern crate tokio_uds;
extern crate u2fhid_protocol;
extern crate users;

use std::io;
use std::os::unix::io::FromRawFd;

use clap::{App, Arg};
use futures::future;
use futures::prelude::*;
use slog::{Drain, Logger};
use systemd::daemon::{is_socket_unix, Listening, SocketType};
use tokio::reactor::Handle;
use tokio::runtime::Runtime;

use device::Device;
use softu2f_system_daemon::*;

mod bidirectional_pipe;
mod device;

const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const PATH_ARG: &str = "path";

fn main() {
    let args = App::new("SoftU2F System Daemon")
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
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let logger = Logger::root(drain, o!());

    info!(logger, "Starting SoftU2F system daemon"; "version" => VERSION);

    run(socket_path, &logger).unwrap_or_else(|err| error!(logger, "Exiting"; "err" => err.to_string()));
}

fn run(socket_path: Option<&str>, logger: &Logger) -> Result<(), device::Error> {
    let mut runtime = Runtime::new()?;
    let handle = runtime.handle();
    runtime.block_on(listen(socket_path, handle, logger))?;
    runtime.shutdown_on_idle().wait().unwrap();
    Ok(())
}

fn listen(socket_path: Option<&str>, handle: &Handle, logger: &Logger) -> Box<dyn Future<Item=(), Error=device::Error> + Send + 'static> {
    let handle = handle.clone();
    let logger = logger.clone();
    match socket_listener(socket_path, &handle) {
        Ok(listener) => Box::new(listener.incoming().from_err().for_each(move |connection| accept(connection, &handle, &logger))),
        Err(err) => Box::new(future::err(err).from_err()),
    }
}

fn socket_listener(socket_path: Option<&str>, handle: &Handle) -> io::Result<tokio_uds::UnixListener> {
    let listener = socket_path
        .map(std::os::unix::net::UnixListener::bind)
        .unwrap_or_else(|| systemd_socket_listener())?;
    tokio_uds::UnixListener::from_std(listener, handle)
}

fn systemd_socket_listener() -> io::Result<std::os::unix::net::UnixListener> {
    let listen_fds = systemd::daemon::listen_fds(true)?;
    if listen_fds != 1 {
        return Err(io::Error::new(io::ErrorKind::Other, "expected exactly one socket from systemd"));
    }

    let fd = systemd::daemon::LISTEN_FDS_START;
    if !is_socket_unix(fd, Some(SocketType::Stream), Listening::IsListening, Some(DEFAULT_SOCKET_PATH))? {
        return Err(io::Error::new(io::ErrorKind::Other, "expected the softu2f socket from systemd"));
    }

    Ok(unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) })
}

fn accept(stream: tokio_uds::UnixStream, handle: &Handle, logger: &Logger,) -> Box<dyn Future<Item = (), Error = device::Error> + Send + 'static> {
    match try_accept(stream, handle, logger) {
        Ok(device) => Box::new(device),
        Err(err) => Box::new(future::err(err).from_err()),
    }
}

fn try_accept(stream: tokio_uds::UnixStream, handle: &Handle, logger: &Logger) -> io::Result<Device> {
    debug!(logger, "accepting connection";
        "local_addr" => ?stream.local_addr()?,
        "peer_addr" => ?stream.peer_addr()?,
        "peer_cred" => ?stream.peer_cred()?);
    Device::new(stream, handle, logger)
}
