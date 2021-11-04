use std::io;

use u2f_core::{ApplicationKey, Counter, SecretStore};

pub(crate) mod file_store;
pub(crate) mod file_store_v2;
pub(crate) mod secret_service_store;

pub type Error = io::Error;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Secret {
    application_key: ApplicationKey,
    counter: Counter,
}

pub trait UserSecretStore: SecretStore {
    fn add_secret(&self, secret: Secret) -> io::Result<()>;
}
