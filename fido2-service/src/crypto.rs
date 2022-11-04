use fido2_api::{
    AuthenticatorData, COSEAlgorithmIdentifier, CredentialId, CredentialPublicKey, EllipticCurve,
    KeyType, PublicKeyCredentialType, RelyingPartyIdentifier, Sha256, Signature, UserHandle,
};
use ring::{
    error, rand,
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};

fn _test() -> Result<(), ring::error::Unspecified> {
    // Generate a key pair in PKCS#8 (v2) format.
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
    // Sign the message "hello, world".
    const MESSAGE: &[u8] = b"hello, world";
    let sig = key_pair.sign(MESSAGE);

    // Normally an application would extract the bytes of the signature and
    // send them in a protocol message to the peer(s). Here we just get the
    // public key key directly from the key pair.
    let peer_public_key_bytes = key_pair.public_key().as_ref();

    // Verify the signature of the message using the public key. Normally the
    // verifier of the message would parse the inputs to this code out of the
    // protocol message(s) sent by the signer.
    let peer_public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
    peer_public_key.verify(MESSAGE, sig.as_ref())?;
    Ok(())
}

pub fn generate_credential_id(
    rng: &dyn rand::SecureRandom,
) -> Result<CredentialId, error::Unspecified> {
    let mut buf = [0u8; 16];
    rng.fill(&mut buf)?;
    Ok(CredentialId::new(&buf))
}

/// https://www.w3.org/TR/webauthn-2/#public-key-credential-source
#[allow(unused)]
pub struct PublicKeyCredentialSource {
    type_: PublicKeyCredentialType,
    id: CredentialId,
    rp_id: RelyingPartyIdentifier,
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
    ) -> Result<Signature, error::Unspecified> {
        let mut message = auth_data.to_bytes();
        message.extend_from_slice(client_data_hash.as_ref());
        self.private_key.sign(rng, &message)
    }

    pub(crate) fn public_key_document(&self) -> PublicKeyDocument {
        self.private_key.public_key_document()
    }

    pub(crate) fn alg(&self) -> COSEAlgorithmIdentifier {
        self.private_key.alg()
    }

    pub(crate) fn credential_public_key(&self) -> CredentialPublicKey {
        self.private_key.credential_public_key()
    }
}

impl TryFrom<PrivateKeyCredentialSource> for PublicKeyCredentialSource {
    type Error = error::Unspecified;

    fn try_from(pkcs: PrivateKeyCredentialSource) -> Result<Self, Self::Error> {
        Ok(Self {
            type_: pkcs.type_,
            id: pkcs.id,
            rp_id: pkcs.rp_id,
            user_handle: pkcs.user_handle,
            private_key: pkcs.private_key_document.try_into()?,
        })
    }
}

enum PrivateKey {
    ES256(signature::EcdsaKeyPair),
}

impl PrivateKey {
    fn sign(
        &self,
        rng: &dyn rand::SecureRandom,
        message: &[u8],
    ) -> Result<Signature, error::Unspecified> {
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
                public_key
                    .x
                    .copy_from_slice(&key_pair.public_key().as_ref()[1..33]);
                public_key
                    .y
                    .copy_from_slice(&key_pair.public_key().as_ref()[33..65]);
                public_key
            }
        }
    }
}

impl TryFrom<PrivateKeyDocument> for PrivateKey {
    type Error = error::Unspecified;

    fn try_from(document: PrivateKeyDocument) -> Result<Self, Self::Error> {
        Ok(match document {
            PrivateKeyDocument::ES256 { pkcs8_bytes } => {
                PrivateKey::ES256(signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
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
    pub rp_id: RelyingPartyIdentifier,
    pub user_handle: UserHandle,
    private_key_document: PrivateKeyDocument,
}

impl PrivateKeyCredentialSource {
    pub fn generate(
        alg: &COSEAlgorithmIdentifier,
        type_: &PublicKeyCredentialType,
        rp_id: &RelyingPartyIdentifier,
        user_handle: &UserHandle,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        let private_key_document = match alg {
            COSEAlgorithmIdentifier::ES256 => PrivateKeyDocument::generate_es256(rng),
            _ => todo!("error that indicated unsupported algorithm"),
        }?;
        Ok(Self {
            type_: type_.clone(),
            id: generate_credential_id(rng)?,
            rp_id: rp_id.clone(),
            user_handle: user_handle.clone(),
            private_key_document,
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum PrivateKeyDocument {
    ES256 { pkcs8_bytes: Vec<u8> },
}

impl PrivateKeyDocument {
    pub fn generate_es256(rng: &dyn rand::SecureRandom) -> Result<Self, error::Unspecified> {
        Ok(Self::ES256 {
            pkcs8_bytes: signature::EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                rng,
            )?
            .as_ref()
            .to_vec(),
        })
    }
}
