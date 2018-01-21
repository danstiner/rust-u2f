use app_id::AppId;
use key_handle::KeyHandle;
use key::Key;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ApplicationKey {
    pub application: AppId,
    pub handle: KeyHandle,
    key: Key,
}

impl ApplicationKey {
    pub fn new(application: AppId, handle: KeyHandle, key: Key) -> ApplicationKey {
        ApplicationKey {
            application: application,
            handle: handle,
            key: key,
        }
    }
    pub(crate) fn key(&self) -> &Key {
        &self.key
    }
}