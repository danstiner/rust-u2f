#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate slog;

extern crate futures;
extern crate futures_cpupool;
extern crate notify_rust;
extern crate serde_json;
extern crate slog_term;
extern crate softu2f_system_daemon;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_serde_bincode;
extern crate tokio_uds;
extern crate u2f_core;
extern crate u2fhid_protocol;

mod file_storage;
mod user_presence;

use std::env;
use std::io;

use futures::future;
use futures::prelude::*;
use slog::{Drain, Logger};
use softu2f_system_daemon::{CreateDeviceRequest, SocketInput, SocketOutput};
use tokio_core::reactor::Core;
use tokio_io::codec::length_delimited;
use tokio_serde_bincode::{ReadBincode, WriteBincode};
use tokio_uds::UnixStream;
use u2f_core::{SecureCryptoOperations, U2F};
use u2fhid_protocol::{Packet, U2FHID};

use file_storage::FileStorage;
use user_presence::NotificationUserPresence;

fn socket_output_to_packet(output_event: SocketOutput) -> Option<Packet> {
    match output_event {
        SocketOutput::Packet(raw_packet) => {
            Some(Packet::from_bytes(&raw_packet.into_bytes()).unwrap())
        }
        _ => None,
    }
}

fn packet_to_socket_input(packet: Packet) -> Box<Future<Item = SocketInput, Error = io::Error>> {
    Box::new(future::ok(SocketInput::Packet(
        softu2f_system_daemon::Packet::from_bytes(&packet.into_bytes()),
    )))
}

fn run(logger: Logger) -> io::Result<()> {
    let mut core = Core::new()?;
    let handle = core.handle();

    let mut store_path = env::home_dir().unwrap();
    store_path.push(".softu2f-secrets.json");

    info!(logger, "Started SoftU2f Session"; "store_path" => store_path.to_str().unwrap());

    info!(logger, "Opening socket");
    let stream = UnixStream::connect(softu2f_system_daemon::SOCKET_PATH, &handle)?;

    let _peer_cred = stream.peer_cred()?;
    // TODO assert peer creds are root

    let length_delimited = length_delimited::FramedWrite::new(stream);
    let length_delimited = length_delimited::FramedRead::new(length_delimited);

    let framed = ReadBincode::new(WriteBincode::<_, SocketInput>::new(length_delimited));
    let socket = framed.map_err(|err: tokio_serde_bincode::Error| match err {
        tokio_serde_bincode::Error::Io(io_err) => io_err,
        other_err => io::Error::new(io::ErrorKind::Other, other_err),
    });

    let create_device_request = CreateDeviceRequest;
    info!(logger, "Sending create device request"; "request" => &create_device_request);
    core.run(
        socket
            .send(SocketInput::CreateDeviceRequest(create_device_request))
            .and_then(|socket| {
                info!(logger, "Sent create device request");
                socket
                    .into_future()
                    .then(|res| -> Box<Future<Item = (), Error = io::Error>> {
                        let (response, socket) = match res {
                            Ok((response, socket)) => (response, socket),
                            Err((err, _socket)) => {
                                // TODO close socket and any clean up
                                return Box::new(future::err(err));
                            }
                        };

                        info!(logger, "Got response"; "response" => &response);
                        match response {
                            Some(SocketOutput::CreateDeviceResponse(create_response)) => {
                                create_response
                            }
                            _ => {
                                return Box::new(future::err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "Expected create device response",
                                )))
                            }
                        };

                        let transport = socket
                            .filter_map(socket_output_to_packet)
                            .with(packet_to_socket_input);

                        let attestation = u2f_core::self_signed_attestation();
                        let user_presence =
                            Box::new(NotificationUserPresence::new(&handle, logger.new(o!())));
                        let operations = Box::new(SecureCryptoOperations::new(attestation));
                        let storage = Box::new(FileStorage::new(store_path).unwrap());

                        let service =
                            U2F::new(user_presence, operations, storage, logger.new(o!())).unwrap();
                        Box::new(U2FHID::bind_service(
                            &handle,
                            transport,
                            service,
                            logger.new(o!()),
                        ))
                    })
            }),
    )?;

    Ok(())
}

fn main() {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let logger = Logger::root(slog_term::FullFormat::new(plain).build().fuse(), o!());

    run(logger).unwrap();
}
