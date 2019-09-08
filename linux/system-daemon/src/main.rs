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

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

fn main() {
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let logger = Logger::root(drain, o!());

    info!(logger, "Starting SoftU2F system daemon"; "version" => VERSION);

    run(&logger).unwrap_or_else(|err| error!(logger, "Failed to run system daemon"; "err" => err.to_string()));
}

fn run(logger: &Logger) -> Result<(), device::Error> {
    let mut runtime = Runtime::new()?;
    let handle = runtime.handle();
    runtime.block_on(listen(handle, logger))?;
    runtime.shutdown_on_idle().wait().unwrap();
    Ok(())
}

fn listen(handle: &Handle, logger: &Logger) -> Box<dyn Future<Item = (), Error = device::Error> + Send + 'static> {
    let handle = handle.clone();
    let logger = logger.clone();
    match systemd_socket_listener(&handle) {
        Ok(listener) => Box::new(listener.incoming().from_err().for_each(move |connection| accept(connection, &handle, &logger))),
        Err(err) => Box::new(future::err(err).from_err()),
    }
}

fn systemd_socket_listener(handle: &Handle) -> io::Result<tokio_uds::UnixListener> {
    let listen_fds = systemd::daemon::listen_fds(true)?;
    if listen_fds != 1 {
        return Err(io::Error::new(io::ErrorKind::Other, "expected exactly one socket from systemd"));
    }

    let fd = systemd::daemon::LISTEN_FDS_START;
    if !is_socket_unix(fd, Some(SocketType::Stream), Listening::IsListening, Some(SOCKET_PATH))? {
        return Err(io::Error::new(io::ErrorKind::Other, "expected the softu2f socket from systemd"));
    }

    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    tokio_uds::UnixListener::from_std(std_listener, handle)
}

fn accept(stream: tokio_uds::UnixStream, handle: &Handle, logger: &Logger,) -> Box<dyn Future<Item = (), Error = device::Error> + Send + 'static> {
    match Device::new(stream, handle, logger) {
        Ok(device) => Box::new(device),
        Err(err) => Box::new(future::err(err).from_err()),
    }
}
