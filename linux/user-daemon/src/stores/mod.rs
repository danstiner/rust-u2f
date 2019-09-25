use u2f_core::{ApplicationKey, Counter};

pub(crate) mod file;
pub(crate) mod file_store_v2;
pub(crate) mod secret_service;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Secret {
    application_key: ApplicationKey,
    counter: Counter,
}
