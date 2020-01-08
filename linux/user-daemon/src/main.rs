extern crate alloc;
extern crate bincode;
extern crate clap;
extern crate core;
extern crate directories;
extern crate dirs;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate futures_cpupool;
#[macro_use]
extern crate lazy_static;
extern crate notify_rust;
#[macro_use]
extern crate quick_error;
extern crate secret_service;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate softu2f_system_daemon;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_serde_bincode;
extern crate tokio_uds;
extern crate u2f_core;
extern crate u2fhid_protocol;

use std::io;

use clap::{App, Arg};
use directories::{ProjectDirs, UserDirs};
use failure::{Compat, Error};
use futures::future;
use futures::prelude::*;
use slog::{Drain, Logger};
use tokio_core::reactor::{Core, Handle};
use tokio_io::codec::length_delimited;
use tokio_serde_bincode::{ReadBincode, WriteBincode};
use tokio_uds::{UCred, UnixStream};
use u2f_core::{SecretStore, SecureCryptoOperations, U2F};
use u2fhid_protocol::{Packet, U2FHID};

use softu2f_system_daemon::{
    CreateDeviceError, CreateDeviceRequest, DeviceDescription, SocketInput, SocketOutput,
};
use storage::AppDirs;
use user_presence::NotificationUserPresence;

mod atomic_file;
mod config;
mod storage;
mod stores;
mod user_presence;

quick_error! {
    #[derive(Debug)]
    pub enum TransportError {
        Io(err: io::Error) {
            from()
            cause(err)
            display("I/O error: {}", err)
        }
        Bincode(err: Box<bincode::ErrorKind>) {
            from()
            cause(err)
            display("Bincode error: {}", err)
        }
        InvalidState(message: &'static str) {
            display("{}", message)
        }
        DeviceCreateFailed(err: CreateDeviceError) {
            display("{:?}", err)
        }
        Failure(err: Compat<Error>) {
            from()
            cause(err)
            display("{}", err)
        }
    }
}

#[derive(Debug, Fail)]
#[fail(display = "home directory path could not be retrieved from the operating system")]
struct HomeDirectoryNotFound;

impl slog::Value for TransportError {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

type Transport = Box<
    dyn Pipe<
        Item = SocketOutput,
        Error = TransportError,
        SinkItem = SocketInput,
        SinkError = TransportError,
    >,
>;

trait Pipe: Stream + Sink {}

impl<'a, T> Pipe for T where T: Stream + Sink + 'a {}

const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const PATH_ARG: &str = "path";

fn main() -> Result<(), TransportError> {
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

    info!(logger, "Starting virtual Universal 2nd Factor device user daemon"; "version" => VERSION);

    let socket_path = socket_path.unwrap_or(softu2f_system_daemon::DEFAULT_SOCKET_PATH);
    let mut core = Core::new()?;
    let handle = core.handle();
    core.run(connect(socket_path, handle, &logger))
}

fn connect(
    socket_path: &str,
    handle: Handle,
    logger: &Logger,
) -> Box<dyn Future<Item = (), Error = TransportError>> {
    let logger = logger.clone();
    debug!(logger, "Opening socket"; "path" => socket_path);
    Box::new(
        UnixStream::connect(socket_path)
            .map_err(TransportError::Io)
            .and_then(|stream| connected(stream, handle, logger)),
    )
}

fn connected(
    stream: UnixStream,
    handle: Handle,
    logger: Logger,
) -> Box<dyn Future<Item = (), Error = TransportError>> {
    match stream
        .peer_cred()
        .map_err(TransportError::Io)
        .and_then(require_root)
    {
        Ok(()) => (),
        Err(err) => return Box::new(future::err(err)),
    };

    let transport = bind_transport(stream);
    let created_device = create_device(transport, logger.clone());

    Box::new(created_device.and_then(move |(device, transport)| {
        bind_service(device, transport, handle, &logger.clone())
    }))
}

fn bind_transport(stream: UnixStream) -> Transport {
    let framed_write = length_delimited::FramedWrite::new(stream);
    let framed_readwrite = length_delimited::FramedRead::new(framed_write);
    let mapped_err = framed_readwrite.sink_from_err().from_err();
    let bincode_read = ReadBincode::new(mapped_err);
    let bincode_readwrite = WriteBincode::<_, SocketInput>::new(bincode_read);
    Box::new(bincode_readwrite)
}

fn create_device<T>(
    transport: T,
    logger: Logger,
) -> Box<dyn Future<Item = (DeviceDescription, T), Error = TransportError>>
where
    T: Sink<SinkItem = SocketInput, SinkError = TransportError>
        + Stream<Item = SocketOutput, Error = TransportError>
        + 'static,
{
    let request = CreateDeviceRequest;
    debug!(logger, "Sending create device request"; "request" => &request);
    let send = transport.send(SocketInput::CreateDeviceRequest(request));
    let created = send.and_then(move |transport| {
        transport
            .into_future()
            .and_then(|(output, transport)| {
                let res = match output {
                    Some(SocketOutput::CreateDeviceResponse(Ok(device))) => {
                        future::ok((device, transport))
                    }
                    Some(SocketOutput::CreateDeviceResponse(Err(err))) => {
                        future::err((TransportError::DeviceCreateFailed(err), transport))
                    }
                    Some(_) => future::err((
                        TransportError::InvalidState("Expected create device response"),
                        transport,
                    )),
                    None => future::err((
                        TransportError::Io(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "Socket transport closed unexpectedly",
                        )),
                        transport,
                    )),
                };
                res
            })
            .or_else(move |(err, mut transport)| {
                transport
                    .close()
                    .into_future()
                    .map_err(
                        move |err| error!(logger, "failed to close transport"; "error" => ?err),
                    )
                    .then(|_| future::err(err))
            })
    });
    Box::new(created)
}

fn bind_service<T>(
    device: DeviceDescription,
    transport: T,
    handle: Handle,
    log: &Logger,
) -> Box<dyn Future<Item = (), Error = TransportError>>
where
    T: Sink<SinkItem = SocketInput, SinkError = TransportError>
        + Stream<Item = SocketOutput, Error = TransportError>
        + 'static,
{
    info!(log, "Virtual U2F device created"; "device_id" => device.id);

    let packet_logger = log.new(o!());
    let transport = transport
        .filter_map(move |output| socket_output_to_packet(&packet_logger, output))
        .with(|packet| future::ok(packet_to_socket_input(packet)));

    let attestation = u2f_core::self_signed_attestation();
    let user_presence = Box::new(NotificationUserPresence::new(&handle, log.new(o!())));
    let operations = Box::new(SecureCryptoOperations::new(attestation));
    let storage = match build_storage(log) {
        Ok(store) => store,
        Err(err) => return Box::new(future::err(TransportError::Failure(err.compat()))),
    };
    let service = match U2F::new(user_presence, operations, storage, log.new(o!())) {
        Ok(service) => service,
        Err(err) => return Box::new(future::err(TransportError::Io(err))),
    };

    info!(log, "Ready to authenticate");

    Box::new(U2FHID::bind_service(
        handle,
        transport,
        service,
        log.new(o!()),
    ))
}

fn socket_output_to_packet(logger: &Logger, event: SocketOutput) -> Option<Packet> {
    match event {
        SocketOutput::Packet(raw_packet) => match Packet::from_bytes(&raw_packet.to_bytes()) {
            Ok(packet) => Some(packet),
            Err(error) => {
                info!(logger, "Bad packet"; "parse_error" => error);
                debug!(logger, "Packet"; "raw_packet" => raw_packet);
                None
            }
        },
        _ => None,
    }
}

fn packet_to_socket_input(packet: Packet) -> SocketInput {
    SocketInput::Packet(softu2f_system_daemon::Packet::from_bytes(
        &packet.into_bytes(),
    ))
}

fn build_storage(log: &Logger) -> Result<Box<dyn SecretStore>, Error> {
    let user_dirs = UserDirs::new().ok_or(HomeDirectoryNotFound)?;
    let project_dirs =
        ProjectDirs::from("com.github", "danstiner", "Rust U2F").ok_or(HomeDirectoryNotFound)?;

    storage::build(
        &AppDirs {
            user_home_dir: user_dirs.home_dir().to_owned(),
            config_dir: project_dirs.config_dir().to_owned(),
            data_local_dir: project_dirs.data_local_dir().to_owned(),
        },
        log,
    )
}

fn require_root(cred: UCred) -> Result<(), TransportError> {
    if cred.uid != 0 {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Expected socket peer to be running as root user",
        )
        .into())
    } else {
        Ok(())
    }
}
