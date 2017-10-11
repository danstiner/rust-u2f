#[macro_use] extern crate assert_matches;

use std::io;

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

struct SoftU2F;

impl SoftU2F {
    pub fn is_valid_key_handle(&self, key_handle: KeyHandle, application: ApplicationParameter) -> io::Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const all_zero_hash: [u8; 32] = [0; 32];

    #[test]
    fn is_valid_key_handle_with_invalid_handle_is_false() {
        let application_parameter = ApplicationParameter(all_zero_hash);
        let key_handle = KeyHandle(all_zero_hash);

        assert_matches!(SoftU2F.is_valid_key_handle(key_handle, application_parameter), Ok(false));
    }
}
