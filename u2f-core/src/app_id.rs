use std::result::Result;

use crate::serde_base64::{from_base64, to_base64};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct AppId(pub(crate) [u8; 32]);

impl AppId {
    pub fn from_bytes(slice: &[u8]) -> AppId {
        assert_eq!(slice.len(), 32);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        AppId(bytes)
    }

    pub fn eq_consttime(&self, other: &AppId) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }

    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }
}

impl AsRef<[u8]> for AppId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Serialize for AppId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        to_base64(&self, serializer)
    }
}

impl<'de> Deserialize<'de> for AppId {
    fn deserialize<D>(deserializer: D) -> Result<AppId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&from_base64(deserializer)?);
        Ok(AppId(bytes))
    }
}

impl std::fmt::Debug for AppId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AppId")
            .field(&base64::encode(&self.0))
            .finish()
    }
}
