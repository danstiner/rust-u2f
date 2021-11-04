extern crate clap;
extern crate futures;
extern crate hostname;
extern crate libc;
extern crate libsystemd;
extern crate nanoid;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate slog;
extern crate slog_journald;
extern crate slog_term;
extern crate softu2f_system_daemon;
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

use std::convert::TryInto;
use std::io;
use std::os::unix::io::FromRawFd;
use std::os::unix::prelude::IntoRawFd;

use clap::{App, Arg};
use futures::future;
use futures::prelude::*;
use libsystemd::activation::IsType;
use slog::{Drain, Logger};
use tokio::reactor::Handle;

use softu2f_system_daemon::DEFAULT_SOCKET_PATH;

use crate::device::Device;

mod bidirectional_pipe;
mod device;

const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const PATH_ARG: &str = "path";

quick_error! {
    #[derive(Debug)]
    enum Error {
        Device(err: device::Error) {
            from()
            source(err)
            display("Device error: {}", err)
        }
        Io(err: io::Error) {
            from()
            source(err)
            display("I/O error: {}", err)
        }
        Systemd(err: libsystemd::errors::SdError) {
            from()
            source(err)
            display("Systemd error: {}", err)
        }
        WrongSocket(message: String) {
            display("{}", message)
        }
        WrongListenFdCount(count: usize) {
            display("Expected one socket from systemd, instead got {}", count)
        }
    }
}

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
    let log = Logger::root(drain, o!());

    info!(log, "starting SoftU2F system daemon"; "version" => VERSION);

    tokio::run(
        listener(socket_path, &log)
            .map_err(|err| error!(log, "failed to start"; "error" => %err))
            .unwrap(),
    );
}

fn listener(
    socket_path: Option<&str>,
    log: &Logger,
) -> Result<impl Future<Item = (), Error = ()>, Error> {
    let accept_log = log.clone();
    let incoming_log = log.clone();
    let accept = move |stream| accept(stream, &accept_log);
    let listener = socket_listener(socket_path)?;
    let incoming = listener.incoming().map_err(
        move |err| error!(incoming_log, "failed to poll for incoming connections"; "error" => %err),
    );
    Ok(incoming.for_each(accept))
}

fn socket_listener(socket_path: Option<&str>) -> Result<tokio_uds::UnixListener, Error> {
    let handle = Handle::default();
    let listener = socket_path
        .map(std::os::unix::net::UnixListener::bind)
        .map(|res| res.map_err(Error::Io))
        .unwrap_or_else(|| systemd_socket_listener())?;
    tokio_uds::UnixListener::from_std(listener, &handle).map_err(Error::Io)
}

fn systemd_socket_listener() -> Result<std::os::unix::net::UnixListener, Error> {
    let descriptors = libsystemd::activation::receive_descriptors(true)?;

    if descriptors.len() != 1 {
        return Err(Error::WrongListenFdCount(descriptors.len()));
    }

    let descriptor = descriptors.into_iter().next().unwrap();

    if !descriptor.is_unix() {
        return Err(Error::WrongSocket(format!(
            "Expected a stream type socket with path {}",
            DEFAULT_SOCKET_PATH
        )));
    }
    Ok(unsafe { std::os::unix::net::UnixListener::from_raw_fd(descriptor.into_raw_fd()) })
}

fn accept(stream: tokio_uds::UnixStream, log: &Logger) -> impl Future<Item = (), Error = ()> {
    debug!(log, "accepting connection";
        "local_addr" => ?stream.local_addr(),
        "peer_addr" => ?stream.peer_addr(),
        "peer_cred" => ?stream.peer_cred());
    tokio::spawn(handle_connection(stream, log)).into_future()
}

fn handle_connection(
    stream: tokio_uds::UnixStream,
    log: &Logger,
) -> impl Future<Item = (), Error = ()> {
    let log_clone = log.clone();
    let device_future = future::result(
        Device::new(stream, &log)
            .map_err(move |err| error!(log_clone, "Failed to create device"; "error" => %err)),
    );
    let log_clone = log.clone();
    device_future.and_then(|device| {
        let device_id = device.id().to_string();
        device.map_err(move |err| error!(log_clone, "Device closed"; "device_id" => device_id, "error" => %err))
    })
}
