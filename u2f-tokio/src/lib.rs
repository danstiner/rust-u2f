#[macro_use] extern crate assert_matches;

use std::io;
use std::result::Result;

type SHA256Hash = [u8; 32];

struct ApplicationParameter (SHA256Hash);

struct ChallengeParameter (SHA256Hash);

struct KeyHandle ([u8; 32]);

struct KeyPair {}

trait Signature : AsRef<[u8]> {}

struct ApplicationKey {
    application_parameter: ApplicationParameter,
    handle: KeyHandle,
    key_pair: KeyPair,
}

struct AttestationCertificate (KeyPair);

enum SignError {}

trait SecureOperations {
    fn generate_application_key() -> io::Result<ApplicationKey>;
    fn generate_attestation_certificate() -> io::Result<AttestationCertificate>;
    fn sign(key: &KeyPair, data: &[u8]) -> Result<Box<Signature>, SignError>;
}

trait SecureStorage {
    fn add_application_key(key: &ApplicationKey) -> io::Result<()>;
    fn get_attestation_certificate() -> io::Result<AttestationCertificate>;
    fn retrieve_application_key(application: ApplicationParameter, handle: &KeyHandle) -> io::Result<Option<ApplicationKey>>;
    fn set_attestation_certificate(key: &AttestationCertificate) -> io::Result<()>;
}

struct Registration {
    user_public_key: Vec<u8>,
    key_handle: KeyHandle,
    attestation_certificate: Vec<u8>,
    signature: Box<Signature>,
}

#[derive(Debug)]
enum RegistrationError {}

struct SoftU2F;

impl SoftU2F {
    pub fn is_valid_key_handle(&self, key_handle: &KeyHandle, application: &ApplicationParameter) -> io::Result<bool> {
        Ok(false)
    }
    pub fn register(&mut self, application: &ApplicationParameter, challenge: &ChallengeParameter) -> Result<Registration, RegistrationError> {
        Ok(Registration {
            user_public_key: Vec::new(),
            key_handle: KeyHandle([0; 32]),
            attestation_certificate: Vec::new(),
            signature: Box::new(RawSignature(Vec::new())),
        })
    }
}

struct RawSignature (Vec<u8>);

impl Signature for RawSignature {}

impl AsRef<[u8]> for RawSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const all_zero_hash: [u8; 32] = [0; 32];

    #[test]
    fn is_valid_key_handle_with_invalid_handle_is_false() {
        let application = ApplicationParameter(all_zero_hash);
        let key_handle = KeyHandle(all_zero_hash);

        assert_matches!(SoftU2F.is_valid_key_handle(&key_handle, &application), Ok(false));
    }

    #[test]
    fn is_valid_key_handle_with_valid_handle_is_true() {
        let mut softu2f = SoftU2F;
        let application = ApplicationParameter(all_zero_hash);
        let challenge = ChallengeParameter(all_zero_hash);
        let registration = softu2f.register(&application, &challenge).unwrap();

        assert_matches!(SoftU2F.is_valid_key_handle(&registration.key_handle, &application), Ok(true));
    }
}
