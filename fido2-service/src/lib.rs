extern crate async_trait;
extern crate base64;
extern crate byteorder;
extern crate futures;
extern crate hex;
extern crate lazy_static;
extern crate openssl;
extern crate pkg_version;
extern crate rand;
extern crate ring;
extern crate serde;
extern crate subtle;
extern crate tokio;

#[cfg(test)]
extern crate assert_matches;

mod authenticator;
mod crypto;
mod secrets;

use std::fmt::Debug;
use std::io;

use fido2_api::StatusCode;
use thiserror::Error;
use tracing::error;

// TODO hack
pub use crate::crypto::PrivateKeyCredentialSource;
pub use crate::secrets::{SecretStoreActual, SimpleSecrets};

pub use crate::authenticator::{
    Authenticator, CredentialHandle, CredentialProtection, SecretStore, UserPresence,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,

    #[error("Invalid Parameter")]
    InvalidParameter,

    #[error("TODO")]
    Unspecified,

    #[error("TODO")]
    NoCredentials,
}

impl Into<StatusCode> for Error {
    fn into(self) -> StatusCode {
        match self {
            Error::Io(_) => StatusCode::Other,
            Error::UnsupportedAlgorithm => StatusCode::UnsupportedAlgorithm,
            Error::InvalidParameter => StatusCode::InvalidParameter,
            Error::Unspecified => StatusCode::Other,
            Error::NoCredentials => StatusCode::NoCredentials,
        }
    }
}

#[derive(Debug, Error)]
pub enum SignError {}

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
