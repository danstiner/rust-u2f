use std::io;

use ctaphid_protocol::REPORT_DESCRIPTOR;
use futures::{SinkExt, StreamExt};
use softu2f_system_daemon::{
    CreateDeviceError, CreateDeviceRequest, DeviceDescription, Report, SocketInput, SocketOutput,
};
use thiserror::Error;
use tokio::net::{
    unix::{SocketAddr, UCred},
    UnixStream,
};
use tokio_linux_uhid::{Bus, CreateParams, InputEvent, OutputEvent, StreamError, UhidDevice};
use tokio_serde::formats::Bincode;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, trace, warn};
use users::get_user_by_uid;

const REPORT_TYPE: u8 = 0;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("Invalid Unicode string")]
    InvalidUnicodeString,
}

pub async fn handle(stream: UnixStream, _addr: SocketAddr) -> Result<(), StreamError> {
    let ucred = stream.peer_cred()?;
    trace!(?ucred, "Handling connection");
    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());
    let mut user_socket: SocketTransport =
        tokio_serde::Framed::new(length_delimited, Bincode::default());

    let mut uhid_device = {
        let result = handle_create_device_request(&mut user_socket, &ucred).await;
        send_create_device_response(&result, &mut user_socket).await?;
        result?
    };

    trace!("UHID device created, starting to pipe HID reports to/from userspace");
    pipe_reports(&mut uhid_device, &mut user_socket).await
}

async fn handle_create_device_request(
    user_socket: &mut SocketTransport,
    ucred: &UCred,
) -> Result<UhidDevice, StreamError> {
    trace!("Ready to create UHID device");
    while let Some(input) = user_socket.next().await {
        match input? {
            SocketInput::CreateDeviceRequest(CreateDeviceRequest) => {
                let create_params = CreateParams {
                    name: device_name(&ucred),
                    phys: String::from(""), // Physical location of device (not relevant)
                    uniq: String::from(""), // Unique identifier of device (serial #) (not relevant)
                    bus: Bus::USB,
                    vendor: 0xffff, // We are not a real vendor or product (http://www.linux-usb.org/usb.ids)
                    product: 0xffff,
                    version: 1,
                    country: 0,
                    data: REPORT_DESCRIPTOR.to_vec(),
                };

                info!(name = %create_params.name, "Creating UHID virtual authenticator device");
                return UhidDevice::create(create_params).await;
            }
            _ => {
                error!("Unexpected input from user socket");
                todo!()
            }
        }
    }

    debug!("Socket closed before create device request was received");
    todo!()
}

async fn send_create_device_response(
    result: &Result<UhidDevice, StreamError>,
    user_socket: &mut SocketTransport,
) -> Result<(), StreamError> {
    trace!(
        "Relaying create device response, success:{}",
        result.is_ok()
    );
    let response = match result {
        Ok(_device) => Ok(DeviceDescription {
            id: String::from("TODO"),
        }),
        Err(StreamError::Io(err)) => {
            warn!("Creating UHID device failed: I/O error: {}", err);
            Err(CreateDeviceError::IoError)
        }
        Err(err) => {
            warn!("Creating UHID device failed: Unknown error: {}", err);
            Err(CreateDeviceError::Unknown)
        }
    };
    user_socket
        .send(SocketOutput::CreateDeviceResponse(response))
        .await?;
    Ok(())
}

async fn pipe_reports(
    uhid_device: &mut UhidDevice,
    user_socket: &mut SocketTransport,
) -> Result<(), StreamError> {
    loop {
        trace!("Select next HID report to pipe");
        (tokio::select! {
            Some(input) = user_socket.next() => match input? {
                SocketInput::Report(report) => {
                    trace!(len = report.data().len(), "Piping report from userspace");
                    uhid_device.send(InputEvent::Input {
                        data: report.into_raw_bytes(),
                    }).await
                }
                SocketInput::CreateDeviceRequest(_) => {
                    warn!("Ignoring create device request, UHID device already created");
                    continue
                },
            },
            Some(output) = uhid_device.next() => match output? {
                OutputEvent::Output { data } => {
                    let report = Report::from_raw_bytes(data);
                    trace!(data_len = report.data().len(), "Piping report from UHID device");
                    user_socket.send(SocketOutput::Report(report)).await.map_err(StreamError::Io)
                },
                OutputEvent::Start { .. } => {
                    trace!("Ignoring Start UHID event");
                    continue
                },
                OutputEvent::Stop { .. } => {
                    trace!("Ignoring Stop UHID event");
                    continue
                },
                OutputEvent::Open { .. } => {
                    trace!("Ignoring Open UHID event");
                    continue
                },
                OutputEvent::Close { .. } => {
                    trace!("Ignoring Close UHID event");
                    continue
                },
                OutputEvent::GetReport { .. } => {
                    trace!("Ignoring GetReport UHID event");
                    continue
                },
                OutputEvent::SetReport { .. } => {
                    trace!("Ignoring SetReport UHID event");
                    continue
                },
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
                if let Some(username) = user.name().to_str() {
                    format!("rust-u2f ({}@{})", username, hostname)
                } else {
                    format!("rust-u2f ({})", hostname)
                }
            } else {
                format!("rust-u2f ({})", hostname)
            }
        }
        Err(err) => {
            warn!(
                ?err,
                "Unable to determine hostname, defaulting to generic device name"
            );
            format!("rust-u2f")
        }
    }
}

fn get_hostname() -> Result<String, Error> {
    let hostname = hostname::get().map_err(Error::Io)?;
    hostname
        .into_string()
        .map_err(|_| Error::InvalidUnicodeString)
}
