use crate::AAGUID;
use fido2_service::CredentialStore;
use thiserror::Error;
use tracing::info;

mod keyring;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    SecretServiceError(#[from] secret_service::Error),

    #[error("{0}")]
    SerializationError(#[from] serde_json::Error),
}

impl From<Error> for fido2_service::Error {
    fn from(error: Error) -> Self {
        fido2_service::Error::Other(Box::new(error))
    }
}

pub fn build() -> Result<Box<dyn CredentialStore<Error = Error>>, Error> {
    info!("Storing secrets on your default keyring using the D-Bus Secret Service API");
    Ok(Box::new(fido2_service::SoftwareCryptoStore::new(
        keyring::Keyring::new()?,
        AAGUID,
    )))
}
