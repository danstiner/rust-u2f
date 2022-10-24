use openssl::x509::X509;
use std::fmt::{self, Debug};

use super::private_key::PrivateKey;

#[derive(Clone)]
pub struct Attestation {
    pub(crate) certificate: AttestationCertificate,
    pub(crate) key: PrivateKey,
}

#[derive(Clone)]
pub struct AttestationCertificate(pub(crate) X509);

impl AttestationCertificate {
    pub(crate) fn from_pem(pem: &str) -> AttestationCertificate {
        AttestationCertificate(X509::from_pem(pem.as_bytes()).unwrap())
    }

    pub(crate) fn to_der(&self) -> Vec<u8> {
        self.0.to_der().unwrap()
    }
}

impl Debug for AttestationCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AttestationCertificate")
    }
}
