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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
