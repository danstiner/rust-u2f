use openssl::ec::EcKey;
use openssl::pkey::Public;

pub struct PublicKey(EcKey<Public>);

impl PublicKey {}

impl From<PublicKey> for EcKey<Public> {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}
