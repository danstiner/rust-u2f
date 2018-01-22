use std::io;
use std::io::Write;

use futures::future;
use futures::prelude::*;
use slog::Logger;
use tokio_core::reactor::Handle;
use tokio_uds::UCred;
use tokio_io::AsyncRead;
use take_mut::take;

use bidirectional_pipe::BidirectionalPipe;
use softu2f_system_daemon::*;
use linux_uhid_tokio::{Bus, CreateParams, InputEvent, OutputEvent, StreamError, UHIDDevice};

const INPUT_REPORT_LEN: u8 = 64;
const OUTPUT_REPORT_LEN: u8 = 64;

// HID Report Descriptor from http://www.usb.org/developers/hidpage/HUTRR48.pdf
const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06,
    0xd0,
    0xf1, // USAGE_PAGE (FIDO Alliance)
    0x09,
    0x01, // USAGE (Keyboard)
    0xa1,
    0x01, // COLLECTION (Application)
    0x09,
    0x20, //   USAGE (Input Report Data)
    0x15,
    0x00, //   LOGICAL_MINIMUM (0)
    0x26,
    0xff,
    0x00, //   LOGICAL_MAXIMUM (255)
    0x75,
    0x08, //   REPORT_SIZE (8)
    0x95,
    INPUT_REPORT_LEN, //   REPORT_COUNT (64)
    0x81,
    0x02, //   INPUT (Data,Var,Abs)
    0x09,
    0x21, //   USAGE(Output Report Data)
    0x15,
    0x00, //   LOGICAL_MINIMUM (0)
    0x26,
    0xff,
    0x00, //   LOGICAL_MAXIMUM (255)
    0x75,
    0x08, //   REPORT_SIZE (8)
    0x95,
    OUTPUT_REPORT_LEN, //   REPORT_COUNT (64)
    0x91,
    0x02, //   OUTPUT (Data,Var,Abs)
    0xc0, // END_COLLECTION
];

type PacketPipe =
    Box<Pipe<Item = Packet, Error = io::Error, SinkItem = Packet, SinkError = io::Error>>;

type SocketPipe = Box<
    Pipe<Item = SocketInput, Error = io::Error, SinkItem = SocketOutput, SinkError = io::Error>,
>;

trait Pipe: Stream + Sink {}

impl<'a, T> Pipe for T
where
    T: Stream + Sink + 'a,
{
}

enum DeviceState {
    Uninitialized(SocketPipe),
    Initialized {
        socket_future: Box<Future<Item = SocketPipe, Error = io::Error>>,
        uhid_transport: PacketPipe,
    },
    Running(BidirectionalPipe<PacketPipe, PacketPipe, io::Error>),
    Closed,
}

pub struct Device {
    handle: Handle,
    state: DeviceState,
    _user: UCred,
    logger: Logger,
}

impl Device {
    pub fn new<T>(user: UCred, socket_transport: T, handle: &Handle, logger: Logger) -> Device
    where
        T: Stream<Item = SocketInput, Error = io::Error>
            + Sink<SinkItem = SocketOutput, SinkError = io::Error>
            + 'static,
    {
        Device {
            handle: handle.clone(),
            logger: logger,
            state: DeviceState::Uninitialized(Box::new(socket_transport)),
            _user: user,
        }
    }
}

fn initialize(
    socket_transport: SocketPipe,
    handle: &Handle,
    logger: &Logger,
    _request: CreateDeviceRequest,
) -> (
    Box<Future<Item = SocketPipe, Error = io::Error>>,
    PacketPipe,
) {
    info!(logger, "initialize");
    let create_params = CreateParams {
        name: String::from("SoftU2F-Linux"),
        phys: String::from(""),
        uniq: String::from(""),
        bus: Bus::USB,
        vendor: 0xffff,
        product: 0xffff,
        version: 0,
        country: 0,
        data: REPORT_DESCRIPTOR.to_vec(),
    };

    let uhid_device = UHIDDevice::create(&handle, create_params, logger.new(o!())).unwrap();
    // TODO chown device to self.user creds
    let uhid_transport = into_transport(uhid_device);

    let socket_future = socket_transport.send(SocketOutput::CreateDeviceResponse(
        CreateDeviceResponse::Success,
    ));

    (Box::new(socket_future), uhid_transport)
}

fn run(
    socket_transport: SocketPipe,
    uhid_transport: PacketPipe,
    logger: &Logger,
) -> BidirectionalPipe<PacketPipe, PacketPipe, io::Error> {
    info!(logger, "run");
    let mapped_socket_transport = Box::new(
        socket_transport
            .filter_map(|event| match event {
                SocketInput::CreateDeviceRequest(_create_request) => None,
                SocketInput::Packet(packet) => Some(packet),
            })
            .with(|packet: Packet| Box::new(future::ok(SocketOutput::Packet(packet)))),
    );

    BidirectionalPipe::new(mapped_socket_transport, uhid_transport)
}

fn into_transport<T: AsyncRead + Write + 'static>(device: UHIDDevice<T>) -> PacketPipe {
    fn stream_error_to_io_error(err: StreamError) -> io::Error {
        match err {
            StreamError::Io(err) => err,
            StreamError::UnknownEventType(_) => {
                io::Error::new(io::ErrorKind::Other, "Unknown event type")
            }
            StreamError::BufferOverflow(_, _) => {
                io::Error::new(io::ErrorKind::Other, "Buffer overflow")
            }
            StreamError::Nul(err) => io::Error::new(io::ErrorKind::Other, err),
            StreamError::Unknown => io::Error::new(io::ErrorKind::Other, "Unknown"),
        }
    }

    Box::new(
        device
            .filter_map(|event| match event {
                OutputEvent::Output { data } => Some(Packet::from_bytes(&data)),
                _ => None,
            })
            .with(|packet: Packet| {
                Box::new(future::ok(InputEvent::Input {
                    data: packet.into_bytes(),
                }))
            })
            .map_err(stream_error_to_io_error)
            .sink_map_err(stream_error_to_io_error),
    )
}

#[derive(PartialEq, Eq)]
enum AsyncLoop<T> {
    Continue,
    NotReady,
    Done(T),
}

impl<T> From<Async<T>> for AsyncLoop<T> {
    fn from(async: Async<T>) -> AsyncLoop<T> {
        match async {
            Async::Ready(x) => AsyncLoop::Done(x),
            Async::NotReady => AsyncLoop::NotReady,
        }
    }
}

impl Future for Device {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        debug!(self.logger, "poll");

        let mut res: io::Result<AsyncLoop<()>> = Ok(AsyncLoop::Continue);
        while let Ok(AsyncLoop::Continue) = res {
            let state = &mut self.state;
            let handle = &self.handle;
            let logger = &self.logger;
            take(state, |state| match state {
                DeviceState::Uninitialized(mut socket_transport) => {
                    debug!(logger, "state unitialized");
                    let input = socket_transport.poll();

                    let input = match input {
                        Ok(Async::Ready(Some(t))) => t,
                        Ok(Async::Ready(None)) => {
                            // TODO do close actions
                            res = Ok(AsyncLoop::Done(()));
                            return DeviceState::Closed;
                        }
                        Ok(Async::NotReady) => {
                            res = Ok(AsyncLoop::NotReady);
                            return DeviceState::Uninitialized(socket_transport);
                        }
                        Err(err) => {
                            res = Err(err);
                            // TODO do close actions
                            return DeviceState::Closed;
                        }
                    };

                    match input {
                        SocketInput::CreateDeviceRequest(request) => {
                            res = Ok(AsyncLoop::Continue);
                            let (socket_future, uhid_transport) =
                                initialize(socket_transport, handle, logger, request);

                            debug!(logger, "initialized");
                            DeviceState::Initialized {
                                socket_future: socket_future,
                                uhid_transport: uhid_transport,
                            }
                        }
                        _ => {
                            res = Ok(AsyncLoop::Continue);
                            DeviceState::Uninitialized(socket_transport)
                        }
                    }
                }
                DeviceState::Initialized {
                    mut socket_future,
                    uhid_transport,
                } => {
                    debug!(logger, "state initialized");
                    match socket_future.poll() {
                        Ok(Async::Ready(socket)) => {
                            let mut pipe = run(socket, uhid_transport, logger);
                            debug!(logger, "poll running");
                            res = pipe.poll().map(|async| async.into());
                            DeviceState::Running(pipe)
                        }
                        Ok(Async::NotReady) => {
                            res = Ok(AsyncLoop::NotReady);
                            DeviceState::Initialized {
                                socket_future: socket_future,
                                uhid_transport: uhid_transport,
                            }
                        }
                        Err(err) => {
                            res = Err(err);
                            // TODO do close actions
                            DeviceState::Closed
                        }
                    }
                }
                DeviceState::Running(mut pipe) => {
                    debug!(logger, "running");
                    res = pipe.poll().map(|async| async.into());
                    DeviceState::Running(pipe)
                }
                DeviceState::Closed => {
                    debug!(logger, "closed");
                    res = Ok(AsyncLoop::Done(()));
                    DeviceState::Closed
                }
            });
        }
        match res {
            Ok(AsyncLoop::Done(x)) => Ok(Async::Ready(x)),
            Ok(AsyncLoop::NotReady) => Ok(Async::NotReady),
            Ok(AsyncLoop::Continue) => unreachable!(),
            Err(err) => Err(err),
        }
    }
}
