extern crate bincode;
extern crate core;
extern crate dirs;
extern crate futures;
extern crate futures_cpupool;
#[macro_use]
extern crate lazy_static;
extern crate notify_rust;
#[macro_use]
extern crate quick_error;
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

use futures::future;
use futures::prelude::*;
use slog::{Drain, Logger};
use tokio_core::reactor::{Core, Handle};
use tokio_io::codec::length_delimited;
use tokio_serde_bincode::{ReadBincode, WriteBincode};
use tokio_uds::{UCred, UnixStream};
use u2f_core::{SecureCryptoOperations, U2F};
use u2fhid_protocol::{Packet, U2FHID};
use file_store::FileStore;
use softu2f_system_daemon::{CreateDeviceRequest, CreateDeviceError, DeviceDescription, SocketInput, SocketOutput};
use user_presence::NotificationUserPresence;

mod file_store;
mod user_presence;

quick_error! {
    #[derive(Debug)]
    pub enum TransportError {
        Io(err: io::Error) {
            from()
        }
        Bincode(err: Box<bincode::ErrorKind>) {
            from()
        }
        InvalidState(message: &'static str) {
            display("{}", message)
        }
        DeviceCreateFailed(err: CreateDeviceError) {
            display("{:?}", err)
        }
    }
}

impl slog::Value for TransportError {
    fn serialize(&self, _record: &slog::Record, key: slog::Key, serializer: &mut dyn slog::Serializer) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

type Transport = Box<dyn Pipe<Item=SocketOutput, Error=TransportError, SinkItem=SocketInput, SinkError=TransportError>>;

trait Pipe: Stream + Sink {}

impl<'a, T> Pipe for T
    where
        T: Stream + Sink + 'a,
{
}

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

fn main() {
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let logger = Logger::root(drain, o!());

    info!(logger, "Starting SoftU2F user daemon"; "version" => VERSION);

    run(logger).unwrap();
}

fn run(logger: Logger) -> Result<(), TransportError> {
    let mut core = Core::new()?;
    let handle = core.handle();
    core.run(connect(softu2f_system_daemon::SOCKET_PATH, handle, logger))
}

fn connect(socket_path: &str, handle: Handle, logger: Logger) -> Box<dyn Future<Item = (), Error = TransportError>> {
    debug!(logger, "Opening socket"; "path" => socket_path);
    Box::new(UnixStream::connect(socket_path).map_err(TransportError::Io).and_then(|stream| connected(stream, handle, logger)))
}

fn connected(stream: UnixStream, handle: Handle, logger: Logger) -> Box<dyn Future<Item = (), Error = TransportError>> {
    match stream.peer_cred().map_err(TransportError::Io).and_then(require_root) {
        Ok(()) => (),
        Err(err) => return Box::new(future::err(err)),
    };

    let transport = bind_transport(stream);
    let created_device = create_device(transport, logger.clone());

    Box::new(created_device.and_then(move |(device, transport)| bind_service(device, transport, handle, &logger.clone())))
}

fn bind_transport(stream: UnixStream) -> Transport {
    let framed_write = length_delimited::FramedWrite::new(stream);
    let framed_readwrite = length_delimited::FramedRead::new(framed_write);
    let mapped_err = framed_readwrite.sink_from_err().from_err();
    let bincode_read = ReadBincode::new(mapped_err);
    let bincode_readwrite = WriteBincode::<_, SocketInput>::new(bincode_read);
    Box::new(bincode_readwrite)
}

fn create_device<T>(transport: T, logger: Logger) -> Box<dyn Future<Item=(DeviceDescription, T), Error=TransportError>> where T: Sink<SinkItem=SocketInput, SinkError=TransportError> + Stream<Item=SocketOutput, Error=TransportError> + 'static {
    let request = CreateDeviceRequest;
    debug!(logger, "Sending create device request"; "request" => &request);
    let send = transport.send(SocketInput::CreateDeviceRequest(request));
    let created = send.and_then(move |transport| {
        transport.into_future().and_then(|(output, transport)| {
            let res = match output {
                Some(SocketOutput::CreateDeviceResponse(Ok(device))) => future::ok((device, transport)),
                Some(SocketOutput::CreateDeviceResponse(Err(err))) => future::err((TransportError::DeviceCreateFailed(err), transport)),
                Some(_) => future::err((TransportError::InvalidState("Expected create device response"), transport)),
                None => future::err((TransportError::Io(io::Error::new(io::ErrorKind::ConnectionAborted, "Socket transport closed unexpectedly")), transport)),
            };
            res
        }).or_else(move |(err, mut transport)| {
            transport.close().into_future().map_err(move |err| error!(logger, "failed to close transport"; "err" => err)).then(|_| future::err(err))
        })
    });
    Box::new(created)
}

fn bind_service<T>(device: DeviceDescription, transport: T, handle: Handle, logger: &Logger) -> Box<dyn Future<Item=(), Error=TransportError>> where T: Sink<SinkItem=SocketInput, SinkError=TransportError> + Stream<Item=SocketOutput, Error=TransportError> + 'static {
    let packet_logger = logger.new(o!());
    let transport = transport
        .filter_map(move |output| socket_output_to_packet(&packet_logger, output))
        .with(|packet| future::ok(packet_to_socket_input(packet)));

    let mut store_path = dirs::home_dir().unwrap();
    store_path.push(".softu2f-secrets.json");
    info!(logger, "Virtual U2F device created"; "device_id" => device.id, "store_path" => store_path.to_str().unwrap());

    let attestation = u2f_core::self_signed_attestation();
    let user_presence = Box::new(NotificationUserPresence::new(&handle, logger.new(o!())));
    let operations = Box::new(SecureCryptoOperations::new(attestation));
    let store = match FileStore::new(store_path) {
        Ok(store) => Box::new(store),
        Err(err) => return Box::new(future::err(TransportError::Io(err))),
    };
    let service = match U2F::new(user_presence, operations, store, logger.new(o!())) {
        Ok(service) => service,
        Err(err) => return Box::new(future::err(TransportError::Io(err))),
    };

    Box::new(U2FHID::bind_service(
        handle,
        transport,
        service,
        logger.new(o!()),
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
    SocketInput::Packet(softu2f_system_daemon::Packet::from_bytes(&packet.into_bytes()))
}

fn require_root(cred: UCred) -> Result<(), TransportError> {
    if cred.uid != 0 {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "Expected socket peer to be running as root user").into())
    } else {
        Ok(())
    }
}
