use std::fmt::{self, Debug};
use std::result::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use openssl::ec::EcKey;

use serde_base64::{to_base64, from_base64};

pub struct Key(pub(crate) EcKey);

impl Key {
    pub fn from_pem(pem: &str) -> Key {
        Key(EcKey::private_key_from_pem(pem.as_bytes()).unwrap())
    }
}

impl Clone for Key {
    fn clone(&self) -> Key {
        Key(self.0.to_owned().unwrap())
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key")
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PrivateKeyAsPEM::from_key(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Key, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(PrivateKeyAsPEM::deserialize(deserializer)?.as_key())
    }
}

struct PrivateKeyAsPEM(Vec<u8>);

impl PrivateKeyAsPEM {
    fn as_key(&self) -> Key {
        Key(EcKey::private_key_from_pem(&self.0).unwrap())
    }

    fn from_key(key: &Key) -> PrivateKeyAsPEM {
        PrivateKeyAsPEM(key.0.private_key_to_pem().unwrap())
    }
}

impl Serialize for PrivateKeyAsPEM {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        to_base64(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PrivateKeyAsPEM {
    fn deserialize<D>(deserializer: D) -> Result<PrivateKeyAsPEM, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(PrivateKeyAsPEM(from_base64(deserializer)?))
    }
}
