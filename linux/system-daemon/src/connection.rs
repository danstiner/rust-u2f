use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use futures::{future, Future, SinkExt, StreamExt};
use pin_project::pin_project;
use softu2f_system_daemon::{
    CreateDeviceRequest, DeviceDescription, Report, SocketInput, SocketOutput,
};
use thiserror::Error;
use tokio::net::{
    unix::{SocketAddr, UCred},
    UnixStream,
};
use tokio_linux_uhid::{Bus, CreateParams, InputEvent, OutputEvent, StreamError, UhidDevice};
use tokio_serde::formats::Bincode;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, trace, warn};
use users::get_user_by_uid;

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

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] io::Error),

    // #[error("Stream error")]
    // StreamError(#[from] StreamError),
    #[error("Invalid Unicode string")]
    InvalidUnicodeString,
}

pub async fn handle(stream: UnixStream, _addr: SocketAddr) -> Result<(), StreamError> {
    let ucred = stream.peer_cred()?;
    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());
    let mut user_socket: SocketTransport =
        tokio_serde::Framed::new(length_delimited, Bincode::default());

    let mut uhid_device = {
        let result = create_uhid_device(&mut user_socket, &ucred).await;
        send_create_device_response(&result, &mut user_socket).await?;
        result?
    };

    pipe_reports(&mut uhid_device, &mut user_socket).await
}

async fn create_uhid_device(
    user_socket: &mut SocketTransport,
    ucred: &UCred,
) -> Result<UhidDevice, StreamError> {
    loop {
        match user_socket.next().await {
            Some(Ok(SocketInput::CreateDeviceRequest(CreateDeviceRequest))) => {
                let create_params = CreateParams {
                    name: device_name(&ucred),
                    phys: String::from(""),
                    uniq: String::from(""),
                    bus: Bus::USB,
                    vendor: 0xffff,
                    product: 0xffff,
                    version: 0,
                    country: 0,
                    data: REPORT_DESCRIPTOR.to_vec(),
                };

                info!(name = %create_params.name, "Creating virtual U2F device");
                return UhidDevice::create(create_params).await;
            }
            _ => return Err(todo!()),
        }
    }
}

async fn send_create_device_response(
    result: &Result<UhidDevice, StreamError>,
    user_socket: &mut SocketTransport,
) -> Result<(), StreamError> {
    user_socket
        .send(SocketOutput::CreateDeviceResponse(Ok(DeviceDescription {
            id: String::from("TODO"),
        })))
        .await;
    todo!()
}

async fn pipe_reports(
    uhid_device: &mut UhidDevice,
    user_socket: &mut SocketTransport,
) -> Result<(), StreamError> {
    loop {
        (tokio::select! {
            Some(input) = user_socket.next() => match input? {
                SocketInput::Report(report) => uhid_device.send(InputEvent::Input {
                    data: report.into_bytes(),
                }).await,
                SocketInput::CreateDeviceRequest(_) => {
                    warn!("Ignoring create device request, UHID device already created");
                    continue
                },
            },
            Some(output) = uhid_device.next() => match output? {
                OutputEvent::Output { data } => user_socket.send(SocketOutput::Report(Report::new(data))).await.map_err(StreamError::Io),
                _ => continue,
            },
        })?;
    }
}

type SocketTransport = tokio_serde::Framed<
    Framed<UnixStream, LengthDelimitedCodec>,
    SocketInput,
    SocketOutput,
    Bincode<SocketInput, SocketOutput>,
>;

fn device_name(ucred: &UCred) -> String {
    match get_hostname() {
        Ok(hostname) => {
            if let Some(user) = get_user_by_uid(ucred.uid()) {
                let username = user.name().to_str().unwrap_or("<unknown>");
                format!("SoftU2F Linux ({}@{})", username, hostname)
            } else {
                format!("SoftU2F Linux ({})", hostname)
            }
        }
        Err(err) => {
            warn!(
                ?err,
                "Unable to determine hostname, defaulting to generic device name"
            );
            format!("SoftU2F Linux")
        }
    }
}

fn get_hostname() -> Result<String, Error> {
    let hostname = hostname::get().map_err(Error::Io)?;
    hostname
        .into_string()
        .map_err(|_| Error::InvalidUnicodeString)
}
