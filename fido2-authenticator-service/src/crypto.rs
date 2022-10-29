use fido2_authenticator_api::{PublicKeyCredentialType, RelyingPartyIdentifier, UserHandle};
use ring::{
    error, rand,
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};

fn test() -> Result<(), ring::error::Unspecified> {
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

/// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
/// Must be at least 16 bytes and include at least 100 bits of entropy
///
#[derive(Serialize, Deserialize)]
struct CredentialId(Vec<u8>);

impl CredentialId {
    pub fn generate(rng: &dyn rand::SecureRandom) -> Result<Self, error::Unspecified> {
        let mut buf = [0u8; 16];
        rng.fill(&mut buf)?;
        Ok(Self(buf.to_vec()))
    }
}

/// https://www.w3.org/TR/webauthn-2/#public-key-credential-source
pub struct PublicKeyCredentialSource {
    type_: PublicKeyCredentialType,
    id: CredentialId,
    rp_id: RelyingPartyIdentifier,
    user_handle: UserHandle,
    private_key: PrivateKey,
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

#[derive(Serialize, Deserialize)]
pub struct PrivateKeyCredentialSource {
    type_: PublicKeyCredentialType,
    id: CredentialId,
    rp_id: RelyingPartyIdentifier,
    user_handle: UserHandle,
    private_key_document: PrivateKeyDocument,
}

impl PrivateKeyCredentialSource {
    pub fn generate(
        type_: &PublicKeyCredentialType,
        rp_id: &RelyingPartyIdentifier,
        user_handle: &UserHandle,
        private_key_document: PrivateKeyDocument,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        Ok(Self {
            type_: type_.clone(),
            id: CredentialId::generate(rng)?,
            rp_id: rp_id.clone(),
            user_handle: user_handle.clone(),
            private_key_document,
        })
    }
}

#[derive(Serialize, Deserialize)]
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
