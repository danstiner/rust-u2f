#[macro_use]
extern crate slog;

extern crate futures;
extern crate libc;
extern crate slog_journald;
extern crate slog_term;
extern crate softu2f_system_daemon;
extern crate systemd;
extern crate take_mut;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_serde_bincode;
extern crate tokio_uds;
extern crate u2fhid_protocol;
extern crate uhid_linux_tokio;

mod bidirectional_pipe;
mod device;

use std::io;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixListener;

use futures::future;
use futures::prelude::*;
use slog::{Drain, Logger};
use systemd::daemon::{is_socket_unix, Listening, SocketType};
use tokio_core::reactor::{Core, Handle};
use tokio_io::codec::length_delimited;
use tokio_serde_bincode::{ReadBincode, WriteBincode};

use softu2f_system_daemon::*;
use device::Device;

fn run(logger: Logger) -> io::Result<()> {
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let listen_fds_count = systemd::daemon::listen_fds(true)?;
    assert_eq!(
        listen_fds_count,
        1,
        "Expect exactly one socket from systemd"
    );

    let fd = systemd::daemon::LISTEN_FDS_START;
    assert!(
        is_socket_unix(
            fd,
            Some(SocketType::Stream),
            Listening::IsListening,
            Some("/run/softu2f/softu2f.sock"),
        )?,
        "Expect the softu2f socket fom systemd"
    );

    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    let listener = tokio_uds::UnixListener::from_listener(listener, &handle)?;
    debug!(logger, "Listening to incoming connections");
    core.run(listener.incoming().for_each(|connection| {
        let (stream, _addr) = connection;
        handle.spawn(accept(stream, &handle, &logger));
        future::ok(())
    }))
}

fn accept(
    stream: tokio_uds::UnixStream,
    handle: &Handle,
    logger: &Logger,
) -> Box<Future<Item = (), Error = ()>> {
    let peer_cred = stream.peer_cred().unwrap();
    let logger = logger.new(o!("uid" => peer_cred.uid));

    info!(logger, "Incoming connection");

    let length_delimited = length_delimited::FramedWrite::new(stream);
    let length_delimited = length_delimited::FramedRead::new(length_delimited);

    let framed = ReadBincode::new(WriteBincode::<_, SocketOutput>::new(length_delimited));
    let mapped_err = framed.map_err(|err: tokio_serde_bincode::Error| match err {
        tokio_serde_bincode::Error::Io(io_err) => io_err,
        other_err => io::Error::new(io::ErrorKind::Other, other_err),
    });

    Box::new(
        Device::new(peer_cred, mapped_err, handle, logger.new(o!())).or_else(move |err| {
            error!(logger, "Error"; "err" => %err);
            future::ok(())
        }),
    )
}

fn main() {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let logger = Logger::root(slog_term::FullFormat::new(plain).build().fuse(), o!());

    run(logger).unwrap();
}
