use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::SinkExt;
use futures::{Sink, Stream};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::Framed;
use tracing::{debug, trace};

use crate::codec::{Bus, Codec, InputEvent, OutputEvent, StreamError, MAX_UHID_EVENT_SIZE};

pub struct UhidDevice {
    transport: Framed<tokio::fs::File, Codec>,
}

/// Parameters used to create UHID devices
pub struct CreateParams {
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub bus: Bus,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub data: Vec<u8>,
}

impl UhidDevice {
    /// Create a UHID device using '/dev/uhid'
    pub async fn create(params: CreateParams) -> Result<Self, StreamError> {
        Self::create_with_path(Path::new("/dev/uhid"), params).await
    }

    /// Create a UHID device using the specified character misc-device file path
    pub async fn create_with_path(path: &Path, params: CreateParams) -> Result<Self, StreamError> {
        let file = tokio::fs::File::open(path).await?;
        let mut transport = Framed::with_capacity(file, Codec, MAX_UHID_EVENT_SIZE);

        debug!("Sending create device input event");
        transport
            .send(InputEvent::Create {
                name: params.name,
                phys: params.phys,
                uniq: params.uniq,
                bus: params.bus,
                vendor: params.vendor,
                product: params.product,
                version: params.version,
                country: params.country,
                data: params.data,
            })
            .await?;

        Ok(Self { transport })
    }

    /// Sends a 'destroy' event to the UHID device and then close it
    pub async fn destroy(mut self) -> Result<(), StreamError> {
        debug!("destroy");
        self.transport.send(InputEvent::Destroy).await?;
        self.transport.flush().await?;
        Ok(())
    }
}

// impl Stream for UhidDevice {
//     type Item = InputEvent;

//     fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         trace!("UhidDevice.poll_next");
//         self.inner.poll_next(cx)
//     }
// }

// impl Sink<OutputEvent> for UhidDevice {
//     type Error = io::Error;

//     fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         self.inner.poll_ready(cx)
//     }

//     fn start_send(self: Pin<&mut Self>, item: OutputEvent) -> Result<(), Self::Error> {
//         self.inner.start_send(item)
//     }

//     fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         self.inner.poll_flush(cx)
//     }

//     fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         self.inner.poll_close(cx)
//     }
// }
