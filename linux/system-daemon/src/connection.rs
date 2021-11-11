use std::{io, rc::Rc};

use futures::SinkExt;
use softu2f_system_daemon::{SocketInput, SocketOutput};
use thiserror::Error;
use tokio::net::{UnixStream, unix::{SocketAddr, UCred}};
use tokio_linux_uhid::{Bus, CreateParams, InputEvent, OutputEvent, StreamError, UhidDevice};
use tokio_serde::formats::Bincode;
use tracing::warn;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

// use crate::bidirectional_pipe::BidirectionalPipe;

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

// type SocketPipe = Box<
//     dyn Pipe<Item = SocketInput, Error = Error, SinkItem = SocketOutput, SinkError = Error>
//         + Send
//         + 'static,
// >;

// trait Pipe: Stream + Sink {}

// impl<'a, T> Pipe for T where T: Stream + Sink + Send + 'a {}

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] io::Error),

    #[error("Bincode error: {0}")]
    Bincode(bincode::ErrorKind),

    // #[error("Stream error")]
    // StreamError(#[from] StreamError),
    #[error("Invalid Unicode string")]
    InvalidUnicodeString,
}

// impl AsyncRead, AsyncWrite

#[derive(Debug)]
pub struct UhidU2fDevice {
    uhid: UhidDevice,
}

impl UhidU2fDevice {
    fn test(&self) {
        // self.uhid.send(item)
    }
}


struct UhidU2fService {
    device: Rc<Option<UhidU2fDevice>>,
}

impl UhidU2fService {
    pub fn new() -> Self {
        todo!()
    }
}

// impl Service<SocketInput> for UhidU2fService {
//     type Response = SocketOutput;
//     type Error = Error;
//     type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, req: SocketInput) -> Self::Future {
//         match req {
//             SocketInput::CreateDeviceRequest(req) => {
//                 let params = CreateParams {
//                     name: get_device_name(user),
//                     phys: String::from(""),
//                     uniq: String::from(""),
//                     bus: Bus::USB,
//                     vendor: 0xffff,
//                     product: 0xffff,
//                     version: 0,
//                     country: 0,
//                     data: REPORT_DESCRIPTOR.to_vec(),
//                 };
//                 self.device = Some(UhidDevice::create(params));
//                 todo!()
//             }
//             SocketInput::Report(report) => {
//                 self.device
//                     .unwrap()
//                     .send_input(&report.into_bytes())
//                     .await;
//             }
//         }
//     }
// }

// fn device_name(ucred: &UCred) -> String {
//     match get_hostname() {
//         Ok(hostname) => {
//             if let Some(user) = get_user_by_uid(ucred.uid) {
//                 let username = user.name().to_str().unwrap_or("<unknown>");
//                 format!("SoftU2F Linux ({}@{})", username, hostname)
//             } else {
//                 format!("SoftU2F Linux ({})", hostname)
//             }
//         }
//         Err(err) => {
//             warn!(?err, "Unable to determine hostname, defaulting to generic device name");
//             format!("SoftU2F Linux")
//         }
//     }
// }

// fn get_hostname() -> Result<String, Error> {
//     let hostname = hostname::get().map_err(Error::Io)?;
//     hostname
//         .into_string()
//         .map_err(|_| Error::InvalidUnicodeString)
// }

pub struct Connection {
    state: ConnectionState,
    peer_cred: UCred,
}

impl Connection {
    pub fn new(stream: UnixStream, addr: SocketAddr) -> io::Result<Self> {
        let peer_cred = stream.peer_cred()?;
        let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());
        let bincoded = tokio_serde::Framed::new(length_delimited, tokio_serde::formats::Bincode::default());
        Ok(Connection {
            state: ConnectionState::Uninitialized(bincoded),
            peer_cred,
        })
    }
}

enum ConnectionState {
    Uninitialized(tokio_serde::Framed<Framed<UnixStream, LengthDelimitedCodec>, SocketInput, SocketOutput, Bincode<SocketInput, SocketOutput>>),
    CreatingUhidDevice {
        // socket_future: Box<dyn Future<Item = SocketPipe, Error = Error> + Send + 'static>,
        // uhid_transport: DevicePipe,
    },
    Running(),
    Closed,
}

// fn initialize(
//     device_id: &str,
//     socket_transport: SocketPipe,
//     log: &Logger,
//     _request: CreateDeviceRequest,
//     user: &UCred,
// ) -> (
//     Box<dyn Future<Item = SocketPipe, Error = Error> + Send>,
//     DevicePipe,
// ) {
//     let create_params = CreateParams {
//         name: get_device_name(user, log),
//         phys: String::from(""),
//         uniq: String::from(""),
//         bus: Bus::USB,
//         vendor: 0xffff,
//         product: 0xffff,
//         version: 0,
//         country: 0,
//         data: REPORT_DESCRIPTOR.to_vec(),
//     };

//     info!(log, "Creating virtual U2F device"; "name" => &create_params.name);
//     let uhid_device = UHIDDevice::create(create_params, log.clone()).unwrap();
//     // TODO chown device to self.user creds
//     let uhid_transport = into_transport(uhid_device);

//     let socket_future = socket_transport
//         .send(SocketOutput::CreateDeviceResponse(Ok(DeviceDescription {
//             id: device_id.to_string(),
//         })))
//         .from_err();

//     (Box::new(socket_future), uhid_transport)
// }

// fn run(
//     socket_transport: SocketPipe,
//     uhid_transport: DevicePipe,
//     logger: &Logger,
// ) -> BidirectionalPipe<DevicePipe, DevicePipe, Error> {
//     trace!(logger, "run");
//     let mapped_socket_transport = Box::new(
//         socket_transport
//             .filter_map(|event| match event {
//                 SocketInput::CreateDeviceRequest(_create_request) => None,
//                 SocketInput::Packet(packet) => Some(packet),
//             })
//             .with(|packet: Packet| Box::new(future::ok(SocketOutput::Packet(packet)))),
//     );

//     BidirectionalPipe::new(mapped_socket_transport, uhid_transport)
// }

// fn into_transport<T: AsyncRead + Write + Send + 'static>(device: UHIDDevice<T>) -> DevicePipe {
//     Box::new(
//         device
//             .filter_map(|event| match event {
//                 OutputEvent::Output { data } => Some(Packet::from_bytes(&data)),
//                 _ => None,
//             })
//             .with(|packet: Packet| {
//                 Box::new(future::ok(InputEvent::Input {
//                     data: packet.into_bytes(),
//                 }))
//             })
//             .map_err(Error::StreamError),
//     )
// }

// #[derive(PartialEq, Eq, Debug)]
// enum AsyncLoop<T> {
//     Continue,
//     NotReady,
//     Done(T),
// }

// impl<T> From<Async<T>> for AsyncLoop<T> {
//     fn from(a: Async<T>) -> AsyncLoop<T> {
//         match a {
//             Async::Ready(x) => AsyncLoop::Done(x),
//             Async::NotReady => AsyncLoop::NotReady,
//         }
//     }
// }

// impl Future for Device {
//     type Item = ();
//     type Error = Error;

//     fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
//         let mut res: Result<AsyncLoop<()>, Self::Error> = Ok(AsyncLoop::Continue);
//         while let Ok(AsyncLoop::Continue) = res {
//             let logger = &self.logger;
//             let state = &mut self.state;
//             let user = &self.user;
//             let device_id = &self.id;
//             take(state, |state| match state {
//                 DeviceState::Uninitialized(mut socket_transport) => {
//                     trace!(logger, "Future::poll"; "state" => "uninitialized");
//                     let input = socket_transport.poll();

//                     let input = match input {
//                         Ok(Async::Ready(Some(t))) => t,
//                         Ok(Async::Ready(None)) => {
//                             // TODO do close actions
//                             res = Ok(AsyncLoop::Done(()));
//                             return DeviceState::Closed;
//                         }
//                         Ok(Async::NotReady) => {
//                             res = Ok(AsyncLoop::NotReady);
//                             return DeviceState::Uninitialized(socket_transport);
//                         }
//                         Err(err) => {
//                             res = Err(err);
//                             // TODO do close actions
//                             return DeviceState::Closed;
//                         }
//                     };

//                     match input {
//                         SocketInput::CreateDeviceRequest(request) => {
//                             res = Ok(AsyncLoop::Continue);
//                             let (socket_future, uhid_transport) =
//                                 initialize(device_id, socket_transport, logger, request, user);

//                             DeviceState::Initialized {
//                                 socket_future,
//                                 uhid_transport,
//                             }
//                         }
//                         _ => {
//                             res = Ok(AsyncLoop::Continue);
//                             DeviceState::Uninitialized(socket_transport)
//                         }
//                     }
//                 }
//                 DeviceState::Initialized {
//                     mut socket_future,
//                     uhid_transport,
//                 } => {
//                     trace!(logger, "initialized");
//                     match socket_future.poll() {
//                         Ok(Async::Ready(socket)) => {
//                             let pipe = run(socket, uhid_transport, logger);
//                             res = Ok(AsyncLoop::Continue);
//                             DeviceState::Running(pipe)
//                         }
//                         Ok(Async::NotReady) => {
//                             res = Ok(AsyncLoop::NotReady);
//                             DeviceState::Initialized {
//                                 socket_future,
//                                 uhid_transport,
//                             }
//                         }
//                         Err(err) => {
//                             res = Err(err);
//                             // TODO do close actions
//                             DeviceState::Closed
//                         }
//                     }
//                 }
//                 DeviceState::Running(mut pipe) => {
//                     trace!(logger, "Future::poll"; "state" => "running");
//                     res = pipe.poll().map(AsyncLoop::from);
//                     DeviceState::Running(pipe)
//                 }
//                 DeviceState::Closed => {
//                     trace!(logger, "Future::poll"; "state" => "closed");
//                     res = Ok(AsyncLoop::Done(()));
//                     DeviceState::Closed
//                 }
//             });
//         }
//         debug!(self.logger, "Future::poll"; "result" => ?res);
//         match res {
//             Ok(AsyncLoop::Done(())) => Ok(Async::Ready(())),
//             Ok(AsyncLoop::NotReady) => Ok(Async::NotReady),
//             Ok(AsyncLoop::Continue) => unreachable!(),
//             Err(err) => Err(err),
//         }
//     }
// }
