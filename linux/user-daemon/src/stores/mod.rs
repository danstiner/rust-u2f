use std::io;

use u2f_core::{ApplicationKey, Counter, SecretStore};

pub(crate) mod file_store;
pub(crate) mod file_store_v2;
pub(crate) mod secret_service_store;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Secret {
    application_key: ApplicationKey,
    counter: Counter,
}

pub trait UserSecretStore: SecretStore {
    fn add_secret(&self, secret: Secret) -> io::Result<()>;
    fn into_u2f_store(self: Box<Self>) -> Box<dyn SecretStore>;
}
