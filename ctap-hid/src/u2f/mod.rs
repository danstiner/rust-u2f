mod app_id;
mod application_key;
mod attestation;
mod constants;
mod key_handle;
mod known_app_ids;
mod private_key;
mod public_key;
mod request;
mod response;
mod self_signed_attestation;
mod serde_base64;

use async_trait::async_trait;
use byteorder::{BigEndian, WriteBytesExt};
use std::fmt::Debug;
use std::io;
use thiserror::Error;
use tracing::error;

use app_id::AppId;
use application_key::ApplicationKey;
use attestation::AttestationCertificate;
use constants::*;
use key_handle::KeyHandle;
use private_key::PrivateKey;
pub use request::Request;
pub use response::Response;

#[derive(Debug)]
pub enum StatusCode {
    NoError,
    TestOfUserPresenceNotSatisfied,
    InvalidKeyHandle,
    RequestLengthInvalid,
    RequestClassNotSupported,
    RequestInstructionNotSuppored,
    UnknownError,
}

impl StatusCode {
    pub fn write<W: WriteBytesExt>(&self, write: &mut W) {
        let value = match self {
            StatusCode::NoError => SW_NO_ERROR,
            StatusCode::TestOfUserPresenceNotSatisfied => SW_CONDITIONS_NOT_SATISFIED,
            StatusCode::InvalidKeyHandle => SW_WRONG_DATA,
            StatusCode::RequestLengthInvalid => SW_WRONG_LENGTH,
            StatusCode::RequestClassNotSupported => SW_CLA_NOT_SUPPORTED,
            StatusCode::RequestInstructionNotSuppored => SW_INS_NOT_SUPPORTED,
            StatusCode::UnknownError => SW_UNKNOWN,
        };
        write.write_u16::<BigEndian>(value).unwrap();
    }
}

#[derive(Debug, Error)]
pub enum SignError {}

pub type Counter = u32;

#[derive(Clone, Debug)]
pub struct Challenge([u8; 32]);

impl AsRef<[u8]> for Challenge {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub trait Signature: AsRef<[u8]> + Debug + Send {}

#[async_trait]
pub trait UserPresence {
    async fn approve_registration(&self, application: &AppId) -> Result<bool, io::Error>;
    async fn approve_authentication(&self, application: &AppId) -> Result<bool, io::Error>;
    async fn wink(&self) -> Result<(), io::Error>;
}

pub trait CryptoOperations {
    fn attest(&self, data: &[u8]) -> Result<Box<dyn Signature>, SignError>;
    fn generate_application_key(&self, application: &AppId) -> io::Result<ApplicationKey>;
    fn get_attestation_certificate(&self) -> AttestationCertificate;
    fn sign(&self, key: &PrivateKey, data: &[u8]) -> Result<Box<dyn Signature>, SignError>;
}

pub trait SecretStore {
    fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()>;
    fn get_and_increment_counter(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Counter>;
    fn retrieve_application_key(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Option<ApplicationKey>>;
}

impl SecretStore for Box<dyn SecretStore> {
    fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()> {
        Box::as_ref(self).add_application_key(key)
    }

    fn get_and_increment_counter(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Counter> {
        Box::as_ref(self).get_and_increment_counter(application, handle)
    }

    fn retrieve_application_key(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Option<ApplicationKey>> {
        Box::as_ref(self).retrieve_application_key(application, handle)
    }
}

#[derive(Debug)]
pub struct Registration {
    user_public_key: Vec<u8>,
    key_handle: KeyHandle,
    attestation_certificate: AttestationCertificate,
    signature: Box<dyn Signature>,
}

#[derive(Debug)]
pub struct Authentication {
    counter: Counter,
    signature: Box<dyn Signature>,
    user_present: bool,
}

#[derive(Debug, Error)]
pub enum AuthenticateError {
    #[error("Approval required")]
    ApprovalRequired,

    #[error("Invalid key handle")]
    InvalidKeyHandle,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Signing error: {0}")]
    Signing(#[from] SignError),
}

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("Approval required")]
    ApprovalRequired,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Signing error: {0}")]
    Signing(#[from] SignError),
}

/// User presence byte [1 byte]. Bit 0 indicates whether user presence was verified.
/// If Bit 0 is is to 1, then user presence was verified. If Bit 0 is set to 0,
/// then user presence was not verified. The values of Bit 1 through 7 shall be 0;
/// different values are reserved for future use.
fn user_presence_byte(user_present: bool) -> u8 {
    let mut byte: u8 = 0b0000_0000;
    if user_present {
        byte |= 0b0000_0001;
    }
    byte
}
