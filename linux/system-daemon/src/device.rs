use std::io;
use std::io::Write;

use futures::future;
use futures::prelude::*;
use hostname::get_hostname;
use slog::Logger;
use take_mut::take;
use tokio::reactor::Handle;
use tokio_io::AsyncRead;
use tokio_io::codec::length_delimited;
use tokio_serde_bincode::{ReadBincode, WriteBincode};
use tokio_uds::{UCred, UnixStream};
use users::get_user_by_uid;

use bidirectional_pipe::BidirectionalPipe;
use softu2f_system_daemon::*;
use tokio_linux_uhid::{Bus, CreateParams, InputEvent, OutputEvent, StreamError, UHIDDevice};

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
    Box<dyn Pipe<Item = Packet, Error = Error, SinkItem = Packet, SinkError = Error> + Send>;

type SocketPipe = Box<dyn Pipe<Item = SocketInput, Error = Error, SinkItem = SocketOutput, SinkError = Error> + Send + 'static>;

trait Pipe: Stream + Sink {}

impl<'a, T> Pipe for T
where
    T: Stream + Sink + Send + 'a,
{
}

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: io::Error) {
            from()
        }
        Bincode(err: Box<bincode::ErrorKind>) {
            from()
        }
        StreamError(err: StreamError) {
            from()
        }
    }
}

impl slog::Value for Error {
    fn serialize(&self, _record: &slog::Record, key: slog::Key, serializer: &mut dyn slog::Serializer) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

enum DeviceState {
    Uninitialized(SocketPipe),
    Initialized {
        socket_future: Box<dyn Future<Item = SocketPipe, Error = Error> + Send + 'static>,
        uhid_transport: PacketPipe,
    },
    Running(BidirectionalPipe<PacketPipe, PacketPipe, Error>),
    Closed,
}

pub struct Device {
    id: String,
    handle: Handle,
    state: DeviceState,
    user: UCred,
    logger: Logger,
}

impl Device {
    pub fn new(stream: UnixStream,
                  handle: &Handle,
                  logger: &Logger) -> io::Result<Device>
    {
        let user = stream.peer_cred()?;
        let id = nanoid::simple();
        Ok(Device {
            id: id.clone(),
            handle: handle.clone(),
            logger: logger.new(o!("device_id" => id)),
            state: DeviceState::Uninitialized(bind_transport(stream)),
            user,
        })
    }
}


fn bind_transport(stream: UnixStream) -> SocketPipe {
    let framed_write = length_delimited::FramedWrite::new(stream);
    let framed_readwrite = length_delimited::FramedRead::new(framed_write);
    let mapped_err = framed_readwrite.sink_from_err().from_err();
    let bincode_read = ReadBincode::new(mapped_err);
    let bincode_readwrite = WriteBincode::<_, SocketOutput>::new(bincode_read);
    Box::new(bincode_readwrite)
}

fn initialize(
    device_id: &str,
    socket_transport: SocketPipe,
    handle: &Handle,
    logger: &Logger,
    _request: CreateDeviceRequest,
    user: &UCred,
) -> (
    Box<dyn Future<Item = SocketPipe, Error = Error> + Send>,
    PacketPipe,
) {
    info!(logger, "initialize");

    let create_params = CreateParams {
        name: get_device_name(user),
        phys: String::from(""),
        uniq: String::from(""),
        bus: Bus::USB,
        vendor: 0xffff,
        product: 0xffff,
        version: 0,
        country: 0,
        data: REPORT_DESCRIPTOR.to_vec(),
    };

    let uhid_device = UHIDDevice::create(&handle, create_params, logger.clone()).unwrap();
    // TODO chown device to self.user creds
    let uhid_transport = into_transport(uhid_device);

    let socket_future = socket_transport.send(SocketOutput::CreateDeviceResponse(
        Ok(DeviceDescription { id: device_id.to_string() }),
    )).from_err();

    (Box::new(socket_future), uhid_transport)
}

fn get_device_name(ucred: &UCred) -> String {
    if let Some(hostname) = get_hostname() {
        if let Some(user) = get_user_by_uid(ucred.uid) {
            let username = user.name().to_str().unwrap_or("<unknown>");
            format!("SoftU2F Linux ({}@{})", username, hostname)
        } else {
            format!("SoftU2F Linux ({})", hostname)
        }
    } else {
        format!("SoftU2F Linux")
    }
}

fn run(
    socket_transport: SocketPipe,
    uhid_transport: PacketPipe,
    logger: &Logger,
) -> BidirectionalPipe<PacketPipe, PacketPipe, Error> {
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

fn into_transport<T: AsyncRead + Write + Send + 'static>(device: UHIDDevice<T>) -> PacketPipe {
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
            .map_err(Error::StreamError),
    )
}

#[derive(PartialEq, Eq)]
enum AsyncLoop<T> {
    Continue,
    NotReady,
    Done(T),
}

impl<T> From<Async<T>> for AsyncLoop<T> {
    fn from(a: Async<T>) -> AsyncLoop<T> {
        match a {
            Async::Ready(x) => AsyncLoop::Done(x),
            Async::NotReady => AsyncLoop::NotReady,
        }
    }
}

impl Future for Device {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        debug!(self.logger, "poll");

        let mut res: Result<AsyncLoop<()>, Self::Error> = Ok(AsyncLoop::Continue);
        while let Ok(AsyncLoop::Continue) = res {
            let handle = &self.handle;
            let logger = &self.logger;
            let state = &mut self.state;
            let user = &self.user;
            let device_id = &self.id;
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
                                initialize(device_id, socket_transport, handle, logger, request, user);

                            debug!(logger, "initialized");
                            DeviceState::Initialized {
                                socket_future,
                                uhid_transport,
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
                                socket_future,
                                uhid_transport,
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
                    res = pipe.poll().map(AsyncLoop::from);
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
            Ok(AsyncLoop::Done(())) => Ok(Async::Ready(())),
            Ok(AsyncLoop::NotReady) => Ok(Async::NotReady),
            Ok(AsyncLoop::Continue) => unreachable!(),
            Err(err) => Err(err),
        }
    }
}
