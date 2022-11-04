use std::io;

use fido2_service::SecretStore;
use serde::{Deserialize, Serialize};
use tracing::info;
use u2f_core::{ApplicationKey, Counter};

use crate::AAGUID;
use secret_service_store::SecretServiceStore;

mod secret_service_store;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Secret {
    application_key: ApplicationKey,
    counter: Counter,
}

pub trait MutableSecretStore {
    fn add_secret(&self, secret: Secret) -> io::Result<()>;
}

pub fn build() -> io::Result<Box<dyn SecretStore<Error = io::Error>>> {
    info!("Storing secrets in your keychain using the D-Bus Secret Service API");
    let store =
        SecretServiceStore::new().map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    Ok(Box::new(fido2_service::SimpleSecrets::new(store, AAGUID)))
}
