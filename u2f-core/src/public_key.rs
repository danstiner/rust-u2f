use openssl::bn::BigNumContext;
use openssl::bn::BigNumContextRef;
use openssl::ec::{self, EcGroup, EcGroupRef, EcKey, EcPoint, EcPointRef};
use openssl::nid;
use std::result::Result;

use constants::EC_POINT_FORMAT_UNCOMPRESSED;
use key::Key;

pub struct PublicKey {
    group: EcGroup,
    point: EcPoint,
}

fn copy_ec_point(point: &EcPointRef, group: &EcGroupRef, ctx: &mut BigNumContextRef) -> EcPoint {
    let form = ec::POINT_CONVERSION_UNCOMPRESSED;
    let bytes = point.to_bytes(&group, form, ctx).unwrap();
    EcPoint::from_bytes(&group, &bytes, ctx).unwrap()
}

impl PublicKey {
    pub(crate) fn from_key(key: &Key, ctx: &mut BigNumContextRef) -> PublicKey {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let point = copy_ec_point(key.0.public_key().unwrap(), &group, ctx);
        PublicKey {
            group: group,
            point: point,
        }
    }

    /// Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
    /// I.e. [0x04, X (32 bytes), Y (32 bytes)] . Where the byte 0x04 denotes the
    /// uncompressed point compression method.
    pub(crate) fn from_bytes(bytes: &[u8], ctx: &mut BigNumContext) -> Result<PublicKey, String> {
        if bytes.len() != 65 {
            return Err(String::from(format!(
                "Expected 65 bytes, found {}",
                bytes.len()
            )));
        }
        if bytes[0] != EC_POINT_FORMAT_UNCOMPRESSED {
            return Err(String::from("Expected uncompressed point"));
        }
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let point = EcPoint::from_bytes(&group, bytes, ctx).unwrap();
        Ok(PublicKey {
            group: group,
            point: point,
        })
    }

    pub(crate) fn to_ec_key(&self) -> EcKey {
        EcKey::from_public_key(&self.group, &self.point).unwrap()
    }

    /// Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
    /// I.e. [0x04, X (32 bytes), Y (32 bytes)] . Where the byte 0x04 denotes the
    /// uncompressed point compression method.
    pub(crate) fn to_raw(&self, ctx: &mut BigNumContext) -> Vec<u8> {
        let form = ec::POINT_CONVERSION_UNCOMPRESSED;
        self.point.to_bytes(&self.group, form, ctx).unwrap()
    }
}
