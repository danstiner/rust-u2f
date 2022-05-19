extern crate bincode;
extern crate bytes;
extern crate serde_derive;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_SOCKET_PATH: &str = "/run/softu2f/softu2f.sock";

#[derive(Serialize, Deserialize)]
pub enum SocketInput {
    CreateDeviceRequest(CreateDeviceRequest),
    Report(Report),
}

#[derive(Serialize, Deserialize)]
pub enum SocketOutput {
    CreateDeviceResponse(Result<DeviceDescription, CreateDeviceError>),
    Report(Report),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateDeviceRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct DeviceDescription {
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, Error)]
pub enum CreateDeviceError {
    #[error("UHID device experienced an I/O Error")]
    IoError,
    #[error("UHID device already exists")]
    AlreadyExists,
    #[error("UHID device closed")]
    Closed,
    #[error("UHID device failed with unknown error")]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Report(Vec<u8>);

impl Report {
    pub fn new(type_: u8, data: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(data.len() + 1);
        bytes.push(type_);
        bytes.extend_from_slice(data);
        Self(bytes)
    }

    pub fn type_(&self) -> u8 {
        self.0[0]
    }

    pub fn data(&self) -> &[u8] {
        &self.0[1..]
    }

    pub fn from_raw_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_raw_bytes(self) -> Vec<u8> {
        self.0
    }
}
