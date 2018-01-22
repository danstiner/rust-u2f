use std::fmt::{self, Debug};
use std::result::Result;
use rand::Rand;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle;

use serde_base64::{to_base64, from_base64};
use constants::MAX_KEY_HANDLE_LEN;

#[derive(Clone, Eq, PartialEq)]
pub struct KeyHandle(Vec<u8>);

impl KeyHandle {
    pub fn from(bytes: &[u8]) -> KeyHandle {
        assert!(bytes.len() <= MAX_KEY_HANDLE_LEN);
        KeyHandle(bytes.to_vec())
    }

    pub fn eq_consttime(&self, other: &KeyHandle) -> bool {
        self.0.len() == other.0.len() && subtle::slices_equal(&self.0, &other.0) == 1
    }
}

impl AsRef<[u8]> for KeyHandle {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Rand for KeyHandle {
    #[inline]
    fn rand<R: Rng>(rng: &mut R) -> KeyHandle {
        let mut bytes = Vec::with_capacity(MAX_KEY_HANDLE_LEN);
        for _ in 0..MAX_KEY_HANDLE_LEN {
            bytes.push(rng.gen::<u8>());
        }
        KeyHandle(bytes)
    }
}

impl Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyHandle")
    }
}

impl Serialize for KeyHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        to_base64(&self, serializer)
    }
}

impl<'de> Deserialize<'de> for KeyHandle {
    fn deserialize<D>(deserializer: D) -> Result<KeyHandle, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(KeyHandle(from_base64(deserializer)?))
    }
}
