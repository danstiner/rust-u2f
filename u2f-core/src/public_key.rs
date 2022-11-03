use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::Public;

use crate::private_key::PrivateKey;

pub struct PublicKey(EcKey<Public>);

impl PublicKey {
    pub(crate) fn from_key(key: &PrivateKey) -> PublicKey {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PublicKey(EcKey::from_public_key(&group, key.0.public_key()).unwrap())
    }

    /// Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
    /// I.e. [0x04, X (32 bytes), Y (32 bytes)] . Where the byte 0x04 denotes the
    /// uncompressed point compression method.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<PublicKey, String> {
        use openssl::ec::EcPoint;

        const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0x04;

        let mut ctx = BigNumContext::new().unwrap();
        if bytes.len() != 65 {
            return Err(format!("Expected 65 bytes, found {}", bytes.len()));
        }
        if bytes[0] != EC_POINT_FORMAT_UNCOMPRESSED {
            return Err(String::from("Expected uncompressed point"));
        }
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let point = EcPoint::from_bytes(&group, bytes, &mut ctx).unwrap();
        Ok(PublicKey(EcKey::from_public_key(&group, &point).unwrap()))
    }

    /// Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
    /// I.e. [0x04, X (32 bytes), Y (32 bytes)] . Where the byte 0x04 denotes the
    /// uncompressed point compression method.
    pub(crate) fn to_raw(&self) -> Vec<u8> {
        let mut ctx = BigNumContext::new().unwrap();
        let form = PointConversionForm::UNCOMPRESSED;
        self.0
            .public_key()
            .to_bytes(self.0.group(), form, &mut ctx)
            .unwrap()
    }
}

impl From<PublicKey> for EcKey<Public> {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}
