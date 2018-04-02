use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use std::io;
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use openssl::pkey::PKey;
use rand::os::OsRng;
use rand::Rng;

use app_id::AppId;
use application_key::ApplicationKey;
use attestation::{Attestation, AttestationCertificate};
use key_handle::KeyHandle;
use key::Key;
use super::CryptoOperations;
use super::Signature;
use super::SignError;

pub struct OpenSSLCryptoOperations {
    attestation: Attestation,
}

impl OpenSSLCryptoOperations {
    pub fn new(attestation: Attestation) -> OpenSSLCryptoOperations {
        OpenSSLCryptoOperations {
            attestation: attestation,
        }
    }

    fn generate_key() -> Key {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        Key(ec_key)
    }

    fn generate_key_handle() -> io::Result<KeyHandle> {
        Ok(OsRng::new()?.gen())
    }
}

impl CryptoOperations for OpenSSLCryptoOperations {
    fn attest(&self, data: &[u8]) -> Result<Box<Signature>, SignError> {
        self.sign(&self.attestation.key, data)
    }

    fn generate_application_key(&self, application: &AppId) -> io::Result<ApplicationKey> {
        let key = Self::generate_key();
        let handle = Self::generate_key_handle()?;
        Ok(ApplicationKey::new(*application, handle, key))
    }

    fn get_attestation_certificate(&self) -> AttestationCertificate {
        self.attestation.certificate.clone()
    }

    fn sign(&self, key: &Key, data: &[u8]) -> Result<Box<Signature>, SignError> {
        let ec_key = key.0.to_owned();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(data).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        Ok(Box::new(RawSignature(signature)))
    }
}

#[derive(Debug)]
struct RawSignature(Vec<u8>);

impl Signature for RawSignature {}

impl AsRef<[u8]> for RawSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
