use std::io;

use app_id::AppId;
use application_key::ApplicationKey;
use attestation::{Attestation, AttestationCertificate};
use key_handle::KeyHandle;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use private_key::PrivateKey;

use super::CryptoOperations;
use super::SignError;
use super::Signature;

pub struct OpenSSLCryptoOperations {
    attestation: Attestation,
}

impl OpenSSLCryptoOperations {
    pub fn new(attestation: Attestation) -> OpenSSLCryptoOperations {
        OpenSSLCryptoOperations {
            attestation: attestation,
        }
    }

    fn generate_key() -> PrivateKey {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        PrivateKey(ec_key)
    }

    fn generate_key_handle() -> io::Result<KeyHandle> {
        Ok(rand::random())
    }
}

impl CryptoOperations for OpenSSLCryptoOperations {
    fn attest(&self, data: &[u8]) -> Result<Box<dyn Signature>, SignError> {
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

    fn sign(&self, key: &PrivateKey, data: &[u8]) -> Result<Box<dyn Signature>, SignError> {
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
