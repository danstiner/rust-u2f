use std::fmt::Debug;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::result::Result;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use async_trait::async_trait;
use byteorder::{BigEndian, WriteBytesExt};
use fido2_authenticator_api::AuthenticatorAPI;
use fido2_authenticator_api::Request;
use fido2_authenticator_api::Response;
use futures::Future;
use thiserror::Error;
pub use tower::Service;
use tracing::{debug, error, info, trace};
use u2f_core::AppId;
use u2f_core::CryptoOperations;
use u2f_core::KeyHandle;
use u2f_core::SecretStore;
use u2f_core::UserPresence;

use crate::attestation::AttestationCertificate;
pub use crate::private_key::PrivateKey;
use crate::public_key::PublicKey;
pub use crate::self_signed_attestation::self_signed_attestation;
use crate::user_presence_byte;
use crate::AuthenticateError;
use crate::Authentication;
use crate::Challenge;
use crate::Counter;
use crate::RegisterError;
use crate::Registration;

/// Service capable of handling the requests defined in the FIDO2 specification.
/// TODO
/// See https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html
/// See https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
///
/// Key storage, cryptographic operations, and user presence checking are
/// separated to pluggable dependencies for flexibility and ease of testing.
pub struct Authenticator<Secrets, Crypto, Presence> {
    pub(crate) secrets: Secrets,
    pub(crate) crypto: Crypto,
    pub(crate) presence: Presence,
}

impl<Secrets, Crypto, Presence> Authenticator<Secrets, Crypto, Presence>
where
    Secrets: SecretStore,
    Crypto: CryptoOperations,
    Presence: UserPresence,
{
    pub fn new(secrets: Secrets, crypto: Crypto, presence: Presence) -> Self {
        Self {
            secrets,
            crypto,
            presence,
        }
    }
}

impl<Secrets, Crypto, Presence> AuthenticatorAPI for Authenticator<Secrets, Crypto, Presence> {
    fn version(&self) -> fido2_authenticator_api::VersionInfo {
        fido2_authenticator_api::VersionInfo {
            version_major: pkg_version::pkg_version_major!(),
            version_minor: pkg_version::pkg_version_minor!(),
            version_build: pkg_version::pkg_version_patch!(),
            wink_supported: true,
        }
    }
}

impl<Secrets, Crypto, Presence> Service<Request> for Authenticator<Secrets, Crypto, Presence>
where
    Secrets: SecretStore + 'static,
    Crypto: CryptoOperations + 'static,
    Presence: UserPresence + 'static,
{
    type Response = Response;
    type Error = super::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // let u2f = Arc::clone(&self.0);
        trace!(?req, "U2fService::call");
        Box::pin(async move {
            match req {
                // Request::Register {
                //     challenge,
                //     application,
                // } => u2f.register_request(application, challenge).await,
                // Request::Authenticate {
                //     control_code,
                //     challenge,
                //     application,
                //     key_handle,
                // } => {
                //     u2f.authenticate_request(control_code, challenge, application, key_handle)
                //         .await
                // }
                Request::GetInfo => {
                    debug!("Get version request");
                    Ok(Response::GetInfo {
                        versions: todo!(),
                        extensions: todo!(),
                        aaguid: todo!(),
                        options: todo!(),
                        max_msg_size: todo!(),
                        pin_uv_auth_protocols: todo!(),
                        max_credential_count_in_list: todo!(),
                        max_credential_id_length: todo!(),
                        transports: todo!(),
                        algorithms: todo!(),
                        max_serialized_large_blob_array: todo!(),
                        force_pin_change: todo!(),
                        min_pin_length: todo!(),
                        firmware_version: todo!(),
                        max_cred_blob_len: todo!(),
                        max_rp_ids_for_set_min_pin_length: todo!(),
                        preferred_platform_uv_attempts: todo!(),
                        uv_modality: todo!(),
                        certifications: todo!(),
                        remaining_discoverable_credentials: todo!(),
                        vendor_prototype_config_commands: todo!(),
                    })
                } // Request::Wink => u2f.wink_request().await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{HasPublic, PKey, PKeyRef};
    use openssl::sign::Verifier;
    use u2f_core::{AppId, ApplicationKey};

    use super::*;
    use crate::attestation::Attestation;
    use crate::Signature;

    fn fake_app_id() -> AppId {
        AppId::from_bytes(&[0u8; 32])
    }

    fn fake_challenge() -> Challenge {
        Challenge([0u8; 32])
    }

    fn fake_key_handle() -> KeyHandle {
        KeyHandle::from(&vec![0u8; 128])
    }

    struct FakeUserPresence {
        pub should_approve_authentication: bool,
        pub should_approve_registration: bool,
    }

    impl FakeUserPresence {
        fn always_approve() -> FakeUserPresence {
            FakeUserPresence {
                should_approve_authentication: true,
                should_approve_registration: true,
            }
        }
    }

    #[async_trait]
    impl UserPresence for FakeUserPresence {
        async fn approve_registration(&self, _: &AppId) -> Result<bool, io::Error> {
            Ok(self.should_approve_registration)
        }
        async fn approve_authentication(&self, _: &AppId) -> Result<bool, io::Error> {
            Ok(self.should_approve_authentication)
        }
        async fn wink(&self) -> Result<(), io::Error> {
            Ok(())
        }
    }

    struct InMemorySecretStore(Mutex<InMemorySecretStoreInner>);

    struct InMemorySecretStoreInner {
        application_keys: HashMap<AppId, ApplicationKey>,
        counters: HashMap<AppId, Counter>,
    }

    impl InMemorySecretStore {
        fn new() -> InMemorySecretStore {
            InMemorySecretStore(Mutex::new(InMemorySecretStoreInner {
                application_keys: HashMap::new(),
                counters: HashMap::new(),
            }))
        }
    }

    #[async_trait]
    impl SecretStore for InMemorySecretStore {
        fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()> {
            self.0
                .lock()
                .unwrap()
                .application_keys
                .insert(key.application, key.clone());
            Ok(())
        }

        fn get_and_increment_counter(
            &self,
            application: &AppId,
            handle: &KeyHandle,
        ) -> Result<Counter, io::Error> {
            let mut borrow = self.0.lock().unwrap();
            if let Some(counter) = borrow.counters.get_mut(application) {
                let counter_value = *counter;
                *counter += 1;
                return Ok(counter_value);
            }

            let initial_counter = 0;
            borrow.counters.insert(*application, initial_counter);
            Ok(initial_counter)
        }

        fn retrieve_application_key(
            &self,
            application: &AppId,
            handle: &KeyHandle,
        ) -> Result<Option<ApplicationKey>, io::Error> {
            let borrow = self.0.lock().unwrap();
            let key = borrow.application_keys.get(application);
            match key {
                Some(key) if key.handle.eq_consttime(handle) => Ok(Some(key.clone())),
                _ => Ok(None),
            }
        }
    }

    fn get_test_attestation() -> Attestation {
        Attestation {
            certificate: AttestationCertificate::from_pem(
                "-----BEGIN CERTIFICATE-----
MIIBfzCCASagAwIBAgIJAJaMtBXq9XVHMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMM
EFNvZnQgVTJGIFRlc3RpbmcwHhcNMTcxMDIwMjE1NzAzWhcNMjcxMDIwMjE1NzAz
WjAbMRkwFwYDVQQDDBBTb2Z0IFUyRiBUZXN0aW5nMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEryDZdIOGjRKLLyG6Mkc4oSVUDBndagZDDbdwLcUdNLzFlHx/yqYl
30rPR35HvZI/zKWELnhl5BG3hZIrBEjpSqNTMFEwHQYDVR0OBBYEFHjWu2kQGzvn
KfCIKULVtb4WZnAEMB8GA1UdIwQYMBaAFHjWu2kQGzvnKfCIKULVtb4WZnAEMA8G
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgaiIS0Rb+Hw8WSO9fcsln
ERLGHDWaV+MS0kr5HgmvAjQCIEU0qjr86VDcpLvuGnTkt2djzapR9iO9PPZ5aErv
3GCT
-----END CERTIFICATE-----",
            ),
            key: PrivateKey::from_pem(
                "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEijhKU+RGVbusHs9jNSUs9ZycXRSvtz0wrBJKozKuh1oAoGCCqGSM49
AwEHoUQDQgAEryDZdIOGjRKLLyG6Mkc4oSVUDBndagZDDbdwLcUdNLzFlHx/yqYl
30rPR35HvZI/zKWELnhl5BG3hZIrBEjpSg==
-----END EC PRIVATE KEY-----",
            ),
        }
    }

    fn verify_signature<T>(signature: &dyn Signature, data: &[u8], public_key: &PKeyRef<T>)
    where
        T: HasPublic,
    {
        let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
        verifier.update(data).unwrap();
        assert!(verifier.verify(signature.as_ref()).unwrap());
    }
}
