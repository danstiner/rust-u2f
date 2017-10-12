#[macro_use]
extern crate assert_matches;
#[macro_use]
extern crate quick_error;

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::io;
use std::result::Result;

type Counter = u32;
type SHA256Hash = [u8; 32];

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct ApplicationParameter(SHA256Hash);

struct ChallengeParameter(SHA256Hash);

#[derive(Copy, Clone, Debug)]
struct KeyHandle([u8; 32]);

#[derive(Copy, Clone, Debug)]
struct KeyPair;

trait Signature: AsRef<[u8]> + Debug {}

#[derive(Copy, Clone, Debug)]
struct ApplicationKey {
    application: ApplicationParameter,
    handle: KeyHandle,
    key_pair: KeyPair,
}

#[derive(Copy, Clone, Debug)]
struct AttestationCertificate {
    key_pair: KeyPair,
}

#[derive(Debug)]
pub enum SignError {}

trait ApprovalService {
    fn approve_registration(&self, application: &ApplicationParameter) -> io::Result<bool>;
    fn approve_authentication(&self, application: &ApplicationParameter) -> io::Result<bool>;
}

trait CryptoOperations {
    fn generate_application_key(
        &self,
        application: &ApplicationParameter,
    ) -> io::Result<ApplicationKey>;
    fn generate_attestation_certificate(&self) -> io::Result<AttestationCertificate>;
    fn sign(&self, key: &KeyPair, data: &[u8]) -> Result<Box<Signature>, SignError>;
}

trait SecretStore {
    fn add_application_key(&mut self, key: &ApplicationKey) -> io::Result<()>;
    fn get_attestation_certificate(&self) -> io::Result<Option<AttestationCertificate>>;
    fn get_then_increment_counter(
        &mut self,
        application: &ApplicationParameter,
    ) -> io::Result<Counter>;
    fn retrieve_application_key(
        &self,
        application: &ApplicationParameter,
        handle: &KeyHandle,
    ) -> io::Result<Option<&ApplicationKey>>;
    fn set_attestation_certificate(
        &mut self,
        attestation_certificate: &AttestationCertificate,
    ) -> io::Result<()>;
}

#[derive(Debug)]
struct Registration {
    user_public_key: Vec<u8>,
    key_handle: KeyHandle,
    attestation_certificate: Vec<u8>,
    signature: Box<Signature>,
}

#[derive(Debug)]
struct Authentication {
    counter: Counter,
    signature: Box<Signature>,
}

quick_error! {
    #[derive(Debug)]
    pub enum AuthenticateError {
        ApprovalRequired
        BadKeyHandle
        Io(err: io::Error) {
            from()
        }
        Signing(err: SignError) {
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum RegisterError {
        ApprovalRequired
        Io(err: io::Error) {
            from()
        }
        Signing(err: SignError) {
            from()
        }
    }
}

struct SoftU2F<'a> {
    attestation_certificate: AttestationCertificate,
    approval: &'a ApprovalService,
    operations: &'a CryptoOperations,
    storage: &'a mut SecretStore,
}

impl<'a> SoftU2F<'a> {
    pub fn new(
        approval: &'a ApprovalService,
        operations: &'a CryptoOperations,
        storage: &'a mut SecretStore,
    ) -> io::Result<SoftU2F<'a>> {
        let attestation_certificate = Self::get_attestation_certificate(operations, storage)?;

        Ok(SoftU2F {
            attestation_certificate: attestation_certificate,
            approval: approval,
            operations: operations,
            storage: storage,
        })
    }

    fn get_attestation_certificate(
        operations: &CryptoOperations,
        storage: &mut SecretStore,
    ) -> io::Result<AttestationCertificate> {
        match storage.get_attestation_certificate()? {
            Some(attestation_certificate) => Ok(attestation_certificate),
            None => {
                let attestation_certificate = operations.generate_attestation_certificate()?;
                storage.set_attestation_certificate(
                    &attestation_certificate,
                )?;
                Ok(attestation_certificate)
            }
        }
    }

    pub fn authenticate(
        &mut self,
        application: &ApplicationParameter,
        challenge: &ChallengeParameter,
        key_handle: &KeyHandle,
    ) -> Result<Authentication, AuthenticateError> {
        if !self.approval.approve_authentication(application)? {
            return Err(AuthenticateError::ApprovalRequired);
        }

        let application_key = match self.storage.retrieve_application_key(
            application,
            key_handle,
        )? {
            Some(key) => *key,
            None => return Err(AuthenticateError::BadKeyHandle),
        };
        let counter = self.storage.get_then_increment_counter(application)?;
        let signature = self.operations.sign(
            &self.attestation_certificate.key_pair,
            &[],
        )?;

        Ok(Authentication {
            counter: counter,
            signature: signature,
        })
    }

    pub fn get_version_string() -> String {
        String::from("U2F_V2")
    }

    pub fn is_valid_key_handle(
        &self,
        key_handle: &KeyHandle,
        application: &ApplicationParameter,
    ) -> io::Result<bool> {
        match self.storage.retrieve_application_key(
            application,
            key_handle,
        )? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    pub fn register(
        &mut self,
        application: &ApplicationParameter,
        challenge: &ChallengeParameter,
    ) -> Result<Registration, RegisterError> {
        if !self.approval.approve_registration(application)? {
            return Err(RegisterError::ApprovalRequired);
        }

        let application_key = self.operations.generate_application_key(application)?;
        self.storage.add_application_key(&application_key)?;
        let signature = self.operations.sign(
            &self.attestation_certificate.key_pair,
            &[],
        )?;

        Ok(Registration {
            user_public_key: Vec::new(),
            key_handle: application_key.handle,
            attestation_certificate: Vec::new(),
            signature: signature,
        })
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

struct FakeApprovalService {
    pub should_approve_authentication: bool,
    pub should_approve_registration: bool,
}

impl FakeApprovalService {
    fn always_approve() -> FakeApprovalService {
        FakeApprovalService {
            should_approve_authentication: true,
            should_approve_registration: true,
        }
    }
}

impl ApprovalService for FakeApprovalService {
    fn approve_authentication(&self, application: &ApplicationParameter) -> io::Result<bool> {
        Ok(self.should_approve_authentication)
    }
    fn approve_registration(&self, application: &ApplicationParameter) -> io::Result<bool> {
        Ok(self.should_approve_registration)
    }
}

struct FakeOperations;

impl CryptoOperations for FakeOperations {
    fn generate_application_key(
        &self,
        application: &ApplicationParameter,
    ) -> io::Result<ApplicationKey> {
        Ok(ApplicationKey {
            application: *application,
            handle: KeyHandle([0; 32]),
            key_pair: KeyPair,
        })
    }
    fn generate_attestation_certificate(&self) -> io::Result<AttestationCertificate> {
        Ok(AttestationCertificate { key_pair: KeyPair })
    }
    fn sign(&self, key: &KeyPair, data: &[u8]) -> Result<Box<Signature>, SignError> {
        Ok(Box::new(RawSignature(Vec::new())))
    }
}

struct InMemoryStorage {
    application_keys: HashMap<ApplicationParameter, ApplicationKey>,
    attestation_certificate: Option<AttestationCertificate>,
    counters: HashMap<ApplicationParameter, Counter>,
}

impl InMemoryStorage {
    pub fn new() -> InMemoryStorage {
        InMemoryStorage {
            application_keys: HashMap::new(),
            attestation_certificate: None,
            counters: HashMap::new(),
        }
    }
}

impl SecretStore for InMemoryStorage {
    fn add_application_key(&mut self, key: &ApplicationKey) -> io::Result<()> {
        self.application_keys.insert(key.application, *key);
        Ok(())
    }

    fn get_attestation_certificate(&self) -> io::Result<Option<AttestationCertificate>> {
        Ok(self.attestation_certificate)
    }

    fn get_then_increment_counter(
        &mut self,
        application: &ApplicationParameter,
    ) -> io::Result<Counter> {
        if let Some(counter) = self.counters.get_mut(application) {
            let counter_value = *counter;
            *counter += 1;
            return Ok(counter_value);
        }

        let initial_counter = 0;
        self.counters.insert(*application, initial_counter);
        Ok(initial_counter)
    }

    fn retrieve_application_key(
        &self,
        application: &ApplicationParameter,
        handle: &KeyHandle,
    ) -> io::Result<Option<&ApplicationKey>> {
        Ok(self.application_keys.get(application))
    }

    fn set_attestation_certificate(
        &mut self,
        attestation_certificate: &AttestationCertificate,
    ) -> io::Result<()> {
        self.attestation_certificate = Some(*attestation_certificate);
        Ok(())
    }
}

// struct TestContext<'a> {
//     softu2f: SoftU2F<'a>,
//     approval: AlwaysApproveService,
//     operations: FakeOperations,
//     storage: InMemoryStorage,
// }

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_ZERO_HASH: [u8; 32] = [0; 32];

    // fn new_test_context<'a>() -> TestContext<'a> {
    //     let approval = AlwaysApproveService;
    //     let operations = FakeOperations;
    //     let mut storage: InMemoryStorage = InMemoryStorage::new();
    //     TestContext {
    //         softu2f: SoftU2F::new(&approval, &operations, &mut storage).unwrap(),
    //         approval: approval,
    //         operations: operations,
    //         storage: storage,
    //     }
    // }

    #[test]
    fn is_valid_key_handle_with_invalid_handle_is_false() {
        let approval = FakeApprovalService::always_approve();
        let operations = FakeOperations;
        let mut storage: InMemoryStorage = InMemoryStorage::new();
        let softu2f = SoftU2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let key_handle = KeyHandle(ALL_ZERO_HASH);

        assert_matches!(
            softu2f.is_valid_key_handle(&key_handle, &application),
            Ok(false)
        );
    }

    #[test]
    fn is_valid_key_handle_with_valid_handle_is_true() {
        let approval = FakeApprovalService::always_approve();
        let operations = FakeOperations;
        let mut storage: InMemoryStorage = InMemoryStorage::new();
        let mut softu2f = SoftU2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = softu2f.register(&application, &challenge).unwrap();

        assert_matches!(
            softu2f.is_valid_key_handle(&registration.key_handle, &application),
            Ok(true)
        );
    }


    #[test]
    fn authenticate_with_invalid_handle_errors() {
        let approval = FakeApprovalService::always_approve();
        let operations = FakeOperations;
        let mut storage: InMemoryStorage = InMemoryStorage::new();
        let mut softu2f = SoftU2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let key_handle = KeyHandle(ALL_ZERO_HASH);

        assert_matches!(
            softu2f.authenticate(&application, &challenge, &key_handle),
            Err(AuthenticateError::BadKeyHandle)
        );
    }

    #[test]
    fn authenticate_with_valid_handle_succeeds() {
        let approval = FakeApprovalService::always_approve();
        let operations = FakeOperations;
        let mut storage: InMemoryStorage = InMemoryStorage::new();
        let mut softu2f = SoftU2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = softu2f.register(&application, &challenge).unwrap();

        softu2f
            .authenticate(&application, &challenge, &registration.key_handle)
            .unwrap();
    }

    #[test]
    fn authenticate_with_rejected_approval_errors() {
        let approval = FakeApprovalService {
            should_approve_authentication: false,
            should_approve_registration: true,
        };
        let operations = FakeOperations;
        let mut storage: InMemoryStorage = InMemoryStorage::new();
        let mut softu2f = SoftU2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = softu2f.register(&application, &challenge).unwrap();

        assert_matches!(
            softu2f.authenticate(&application, &challenge, &registration.key_handle),
            Err(AuthenticateError::ApprovalRequired)
        );
    }


    #[test]
    fn register_with_rejected_approval_errors() {
        let approval = FakeApprovalService {
            should_approve_authentication: true,
            should_approve_registration: false,
        };
        let operations = FakeOperations;
        let mut storage: InMemoryStorage = InMemoryStorage::new();
        let mut softu2f = SoftU2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);

        assert_matches!(
            softu2f.register(&application, &challenge),
            Err(RegisterError::ApprovalRequired)
        );
    }
}
