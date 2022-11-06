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

    pub(crate) fn alg(&self) -> COSEAlgorithmIdentifier {
        self.private_key.alg()
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

    pub(crate) fn public_key_document(&self) -> PublicKeyDocument {
        self.private_key.public_key_document()
    }
}

enum PrivateKey {
    ES256(signature::EcdsaKeyPair),
}

impl PrivateKey {
    fn sign(&self, rng: &dyn rand::SecureRandom, message: &[u8]) -> Result<Signature, Unspecified> {
        match self {
            PrivateKey::ES256(key_pair) => match key_pair.sign(rng, message) {
                Ok(signature) => Ok(Signature::new(signature.as_ref())),
                Err(err) => Err(err),
            },
        }
    }

    fn public_key_document(&self) -> PublicKeyDocument {
        match self {
            PrivateKey::ES256(key_pair) => {
                PublicKeyDocument(key_pair.public_key().as_ref().to_vec())
            }
        }
    }

    fn alg(&self) -> COSEAlgorithmIdentifier {
        match self {
            PrivateKey::ES256(_) => COSEAlgorithmIdentifier::ES256,
        }
    }

    fn credential_public_key(&self) -> CredentialPublicKey {
        match self {
            PrivateKey::ES256(key_pair) => {
                let mut public_key = CredentialPublicKey {
                    kty: KeyType::EC2,
                    alg: self.alg(),
                    crv: EllipticCurve::P256,
                    x: [0u8; 32],
                    y: [0u8; 32],
                };
                get_public_numbers(key_pair, &mut public_key.x, &mut public_key.y);
                public_key
            }
        }
    }
}

/// Extract public numbers from a EcdsaKeyPair.
fn get_public_numbers(key_pair: &EcdsaKeyPair, x: &mut [u8; 32], y: &mut [u8; 32]) {
    // The public key is encoded in uncompressed form using the Octet-String-to-Elliptic-Curve-Point
    // algorithm in [SEC 1: Elliptic Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
    let public = key_pair.public_key().as_ref();

    // Assert uncompressed encoding form
    assert_eq!(public[0], 0x04);

    x.copy_from_slice(&public[1..33]);
    y.copy_from_slice(&public[33..65]);
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
        })
    }
}

pub(crate) struct PublicKeyDocument(Vec<u8>);

impl AsRef<[u8]> for PublicKeyDocument {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateKeyCredentialSource {
    pub type_: PublicKeyCredentialType,
    pub id: CredentialId,
    pub rp: PublicKeyCredentialRpEntity,
    pub user_handle: UserHandle,
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
            _ => todo!("error that indicated unsupported algorithm"),
        }?;
        Ok(Self {
            type_: parameters.type_.clone(),
            id: generate_credential_id(rng)?,
            rp: rp.clone(),
            user_handle: user_handle.clone(),
            private_key_document,
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

#[derive(Serialize, Deserialize, Clone)]
pub enum PrivateKeyDocument {
    ES256 { pkcs8_bytes: Vec<u8> },
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
}
