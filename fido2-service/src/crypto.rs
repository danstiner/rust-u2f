use fido2_api::{
    AuthenticatorData, COSEAlgorithmIdentifier, CredentialId, CredentialPublicKey, EllipticCurve,
    KeyType, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity, PublicKeyCredentialType, Sha256, Signature, UserHandle,
};
use ring::{
    error::Unspecified,
    rand,
    signature::{self, EcdsaKeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as, DisplayFromStr};

use crate::{CredentialHandle, KeyProtection};

pub fn generate_credential_id(rng: &dyn rand::SecureRandom) -> Result<CredentialId, Unspecified> {
    let mut buf = [0u8; 16];
    rng.fill(&mut buf)?;
    Ok(CredentialId::new(&buf))
}

/// https://www.w3.org/TR/webauthn-2/#public-key-credential-source
#[allow(unused)]
pub struct PublicKeyCredentialSource {
    type_: PublicKeyCredentialType,
    id: CredentialId,
    rp: PublicKeyCredentialRpEntity,
    user_handle: UserHandle,
    private_key: PrivateKey,
}

impl PublicKeyCredentialSource {
    /// https://www.w3.org/TR/webauthn-2/#fig-signature
    pub fn sign(
        &self,
        auth_data: &AuthenticatorData,
        client_data_hash: &Sha256,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Signature, Unspecified> {
        let mut message = auth_data.to_bytes();
        message.extend_from_slice(client_data_hash.as_ref());
        self.private_key.sign(rng, &message)
    }

    pub(crate) fn credential_public_key(&self) -> CredentialPublicKey {
        self.private_key.credential_public_key()
    }
}

impl TryFrom<PrivateKeyCredentialSource> for PublicKeyCredentialSource {
    type Error = Unspecified;

    fn try_from(pkcs: PrivateKeyCredentialSource) -> Result<Self, Self::Error> {
        Ok(Self {
            type_: pkcs.type_,
            id: pkcs.id,
            rp: pkcs.rp,
            user_handle: pkcs.user_handle,
            private_key: pkcs.private_key_document.try_into()?,
        })
    }
}

/// https://www.w3.org/TR/webauthn-2/#public-key-credential-source
#[allow(unused)]
pub struct AttestationSource {
    private_key: PrivateKey,
}

impl AttestationSource {
    pub fn generate(rng: &dyn rand::SecureRandom) -> Result<Self, Unspecified> {
        Ok(Self {
            private_key: PrivateKeyDocument::generate_es256(rng)?.try_into()?,
        })
    }

    /// https://www.w3.org/TR/webauthn-2/#fig-signature
    pub fn sign(
        &self,
        auth_data: &AuthenticatorData,
        client_data_hash: &Sha256,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Signature, Unspecified> {
        let mut message = auth_data.to_bytes();
        message.extend_from_slice(client_data_hash.as_ref());
        self.private_key.sign(rng, &message)
    }
}

enum PrivateKey {
    ES256(signature::EcdsaKeyPair),
    ES384(signature::EcdsaKeyPair),
}

impl PrivateKey {
    fn sign(&self, rng: &dyn rand::SecureRandom, message: &[u8]) -> Result<Signature, Unspecified> {
        match self {
            PrivateKey::ES256(key_pair) => match key_pair.sign(rng, message) {
                Ok(signature) => Ok(Signature::new(signature.as_ref())),
                Err(err) => Err(err),
            },
            PrivateKey::ES384(key_pair) => match key_pair.sign(rng, message) {
                Ok(signature) => Ok(Signature::new(signature.as_ref())),
                Err(err) => Err(err),
            },
        }
    }

    #[cfg(test)]
    fn public_key_document(&self) -> PublicKeyDocument {
        match self {
            PrivateKey::ES256(key_pair) => {
                PublicKeyDocument(key_pair.public_key().as_ref().to_vec())
            }
            PrivateKey::ES384(key_pair) => {
                PublicKeyDocument(key_pair.public_key().as_ref().to_vec())
            }
        }
    }

    fn alg(&self) -> COSEAlgorithmIdentifier {
        match self {
            PrivateKey::ES256(_) => COSEAlgorithmIdentifier::ES256,
            PrivateKey::ES384(_) => COSEAlgorithmIdentifier::ES384,
        }
    }

    fn credential_public_key(&self) -> CredentialPublicKey {
        match self {
            PrivateKey::ES256(key_pair) => {
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];

                get_public_numbers_es256(key_pair, &mut x, &mut y);

                CredentialPublicKey {
                    kty: KeyType::EC2,
                    alg: self.alg(),
                    crv: EllipticCurve::P256,
                    x: x.to_vec(),
                    y: y.to_vec(),
                }
            }
            PrivateKey::ES384(key_pair) => {
                let mut x = [0u8; 48];
                let mut y = [0u8; 48];

                get_public_numbers_es384(key_pair, &mut x, &mut y);

                CredentialPublicKey {
                    kty: KeyType::EC2,
                    alg: self.alg(),
                    crv: EllipticCurve::P384,
                    x: x.to_vec(),
                    y: y.to_vec(),
                }
            }
        }
    }
}

/// Extract public numbers from a ES256 EcdsaKeyPair.
fn get_public_numbers_es256(key_pair: &EcdsaKeyPair, x: &mut [u8; 32], y: &mut [u8; 32]) {
    // The public key is encoded in uncompressed form using the Octet-String-to-Elliptic-Curve-Point
    // algorithm in [SEC 1: Elliptic Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
    let public = key_pair.public_key().as_ref();

    // Assert uncompressed encoding form
    assert_eq!(public[0], 0x04);

    x.copy_from_slice(&public[1..33]);
    y.copy_from_slice(&public[33..65]);
}

/// Extract public numbers from a P256 EcdsaKeyPair.
fn get_public_numbers_es384(key_pair: &EcdsaKeyPair, x: &mut [u8; 48], y: &mut [u8; 48]) {
    // The public key is encoded in uncompressed form using the Octet-String-to-Elliptic-Curve-Point
    // algorithm in [SEC 1: Elliptic Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
    let public = key_pair.public_key().as_ref();

    // Assert uncompressed encoding form
    assert_eq!(public[0], 0x04);

    x.copy_from_slice(&public[1..49]);
    y.copy_from_slice(&public[49..97]);
}

impl TryFrom<PrivateKeyDocument> for PrivateKey {
    type Error = Unspecified;

    fn try_from(document: PrivateKeyDocument) -> Result<Self, Self::Error> {
        Ok(match document {
            PrivateKeyDocument::ES256 { pkcs8_bytes } => {
                PrivateKey::ES256(signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &pkcs8_bytes,
                )?)
            }
            PrivateKeyDocument::ES384 { pkcs8_bytes } => {
                PrivateKey::ES384(signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    &pkcs8_bytes,
                )?)
            }
        })
    }
}

pub(crate) struct PublicKeyDocument(Vec<u8>);

impl AsRef<[u8]> for PublicKeyDocument {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateKeyCredentialSource {
    #[serde(alias = "type")]
    #[serde_as(as = "DisplayFromStr")]
    pub type_: PublicKeyCredentialType,
    #[serde_as(as = "Base64")]
    pub id: CredentialId,
    pub rp: PublicKeyCredentialRpEntity,
    #[serde_as(as = "Base64")]
    pub user_handle: UserHandle,
    pub sign_count: u32,
    private_key_document: PrivateKeyDocument,
}

impl PrivateKeyCredentialSource {
    pub fn generate(
        parameters: &PublicKeyCredentialParameters,
        rp: &PublicKeyCredentialRpEntity,
        user_handle: &UserHandle,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, Unspecified> {
        let private_key_document = match parameters.alg {
            COSEAlgorithmIdentifier::ES256 => PrivateKeyDocument::generate_es256(rng),
            COSEAlgorithmIdentifier::ES384 => PrivateKeyDocument::generate_es384(rng),
            _ => todo!("error that indicates unsupported algorithm"),
        }?;
        Ok(Self {
            type_: parameters.type_.clone(),
            id: generate_credential_id(rng)?,
            rp: rp.clone(),
            user_handle: user_handle.clone(),
            private_key_document,
            sign_count: 0,
        })
    }

    pub fn handle(&self) -> CredentialHandle {
        CredentialHandle {
            descriptor: self.descriptor(),
            protection: KeyProtection {
                is_user_verification_required: false,
                is_user_verification_optional_with_allow_list: false,
            },
            rp: self.rp.clone(),
        }
    }

    pub fn descriptor(&self) -> PublicKeyCredentialDescriptor {
        PublicKeyCredentialDescriptor {
            type_: self.type_.clone(),
            id: self.id.clone(),
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub enum PrivateKeyDocument {
    ES256 {
        #[serde_as(as = "Base64")]
        pkcs8_bytes: Vec<u8>,
    },
    ES384 {
        #[serde_as(as = "Base64")]
        pkcs8_bytes: Vec<u8>,
    },
}

impl PrivateKeyDocument {
    pub fn generate_es256(rng: &dyn rand::SecureRandom) -> Result<Self, Unspecified> {
        Ok(Self::ES256 {
            pkcs8_bytes: signature::EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                rng,
            )?
            .as_ref()
            .to_vec(),
        })
    }

    pub fn generate_es384(rng: &dyn rand::SecureRandom) -> Result<Self, Unspecified> {
        Ok(Self::ES384 {
            pkcs8_bytes: signature::EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                rng,
            )?
            .as_ref()
            .to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_public_key() {
        let rng = ring::rand::SystemRandom::new();
        let private_key: PrivateKey = PrivateKeyDocument::generate_es256(&rng)
            .unwrap()
            .try_into()
            .unwrap();

        let public_key = private_key.credential_public_key();

        let mut public_key_bytes = Vec::new();
        public_key_bytes.push(0x04); // uncompressed
        public_key_bytes.extend_from_slice(&public_key.x);
        public_key_bytes.extend_from_slice(&public_key.y);
        assert_eq!(
            &public_key_bytes,
            private_key.public_key_document().as_ref()
        );

        // Assert the public key can be used to verify a signature from the private key
        let message = b"message";

        let mut public_key_bytes = Vec::new();
        public_key_bytes.push(0x04); // uncompressed
        public_key_bytes.extend_from_slice(&public_key.x);
        public_key_bytes.extend_from_slice(&public_key.y);
        assert_eq!(
            &public_key_bytes,
            private_key.public_key_document().as_ref()
        );
        let unparsed_public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &public_key_bytes,
        );

        let signature = private_key.sign(&rng, message).unwrap();
        assert!(unparsed_public_key
            .verify(message, signature.as_ref())
            .is_ok());
    }
}
