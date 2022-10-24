use serde::{Deserialize, Serialize};

use super::app_id::AppId;
use super::key_handle::KeyHandle;
use super::private_key::PrivateKey;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ApplicationKey {
    pub application: AppId,
    pub handle: KeyHandle,
    key: PrivateKey,
}

impl ApplicationKey {
    pub fn new(application: AppId, handle: KeyHandle, key: PrivateKey) -> ApplicationKey {
        ApplicationKey {
            application,
            handle,
            key,
        }
    }
    pub(crate) fn key(&self) -> &PrivateKey {
        &self.key
    }
}
