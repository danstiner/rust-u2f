use std::fmt::{self, Debug};
use std::result::Result;

use crate::serde_base64::{from_base64, to_base64};
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;

const DEFAULT_KEY_HANDLE_LEN: usize = 255;
const MAX_KEY_HANDLE_LEN: usize = 255;

#[derive(Clone, Eq, PartialEq)]
pub struct KeyHandle(Vec<u8>);

impl KeyHandle {
    pub fn from(bytes: &[u8]) -> KeyHandle {
        assert!(bytes.len() <= MAX_KEY_HANDLE_LEN);
        KeyHandle(bytes.to_vec())
    }

    pub fn eq_consttime(&self, other: &KeyHandle) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }

    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }
}

impl AsRef<[u8]> for KeyHandle {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Distribution<KeyHandle> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> KeyHandle {
        KeyHandle(
            Standard
                .sample_iter(rng)
                .take(DEFAULT_KEY_HANDLE_LEN)
                .collect(),
        )
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
