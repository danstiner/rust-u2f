use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    #[error("I/O Error")]
    IOError,
    #[error("Already exists")]
    AlreadyExists,
    #[error("closed")]
    Closed,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Report {
    bytes: Vec<u8>,
}

impl Report {
    pub fn from_bytes(bytes: &[u8]) -> Report {
        Report {
            bytes: bytes.to_vec(),
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
