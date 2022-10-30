use openssl::x509::X509;
use std::fmt::{self, Debug};

#[derive(Clone)]
pub struct Attestation {}

#[derive(Clone)]
pub struct AttestationCertificate(pub(crate) X509);

impl AttestationCertificate {
    pub(crate) fn to_der(&self) -> Vec<u8> {
        self.0.to_der().unwrap()
    }
}

impl Debug for AttestationCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AttestationCertificate")
    }
}
