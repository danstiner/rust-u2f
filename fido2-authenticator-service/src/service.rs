use std::pin::Pin;
use std::result::Result;
use std::task::Context;
use std::task::Poll;

use fido2_authenticator_api::Aaguid;
use fido2_authenticator_api::AuthenticatorAPI;
use fido2_authenticator_api::COSEAlgorithmIdentifier;
use fido2_authenticator_api::Command;
use fido2_authenticator_api::GetInfoResponse;
use fido2_authenticator_api::MakeCredentialCommand;
use fido2_authenticator_api::MakeCredentialResponse;
use fido2_authenticator_api::PublicKeyCredentialParameters;
use fido2_authenticator_api::Response;
use futures::Future;
use tower::Service;
use tracing::{debug, trace};
use u2f_core::CryptoOperations;
use u2f_core::SecretStore;
use u2f_core::UserPresence;

use crate::Error;

// Unique identifier of the "make and model" of this virtual authenticator
const AAGUID: Aaguid = Aaguid(uuid::uuid!("5fd220bb-7791-4be4-99c3-1f8d26189e92"));

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

    fn get_info_internal(&self) -> GetInfoResponse {
        GetInfoResponse {
            versions: vec![String::from("FIDO_2_1"), String::from("U2F_V2")],
            extensions: None,
            aaguid: AAGUID,
            options: None,
            max_msg_size: None,
            pin_uv_auth_protocols: None,
            max_credential_count_in_list: None,
            max_credential_id_length: None,
            transports: None,
            algorithms: Some(vec![PublicKeyCredentialParameters::es256()]),
            max_serialized_large_blob_array: None,
            force_pin_change: None,
            min_pin_length: None,
            firmware_version: None,
            max_cred_blob_len: None,
            max_rp_ids_for_set_min_pin_length: None,
            preferred_platform_uv_attempts: None,
            uv_modality: None,
            certifications: None,
            remaining_discoverable_credentials: Some(0),
            vendor_prototype_config_commands: None,
        }
    }
}

impl<Secrets, Crypto, Presence> AuthenticatorAPI for Authenticator<Secrets, Crypto, Presence>
where
    Secrets: SecretStore + 'static,
    Crypto: CryptoOperations + 'static,
    Presence: UserPresence + 'static,
{
    fn version(&self) -> fido2_authenticator_api::VersionInfo {
        fido2_authenticator_api::VersionInfo {
            version_major: pkg_version::pkg_version_major!(),
            version_minor: pkg_version::pkg_version_minor!(),
            version_build: pkg_version::pkg_version_patch!(),
            wink_supported: false,
        }
    }

    fn make_credential(&self, cmd: MakeCredentialCommand) -> Result<MakeCredentialResponse, Error> {
        let MakeCredentialCommand {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
            enterprise_attestation,
        } = cmd;
        debug!(rp = ?rp, user = ?user, "make_credential");

        // See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-makeCred-platf-actions

        // TODO If authenticator supports either pinUvAuthToken or clientPin features and the platform sends a zero length pinUvAuthParam:

        // TODO If the pinUvAuthParam parameter is present:

        // Validate pubKeyCredParams with the following steps:

        // TODO Push this down into CBOR/Command validation level
        // If the element is missing required members, including members that are mandatory only for the specific type, then return an error, for example CTAP2_ERR_INVALID_CBOR.
        // If the values of any known members have the wrong type then return an error, for example CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
        // Note: This means always iterating over every element of pubKeyCredParams to validate them.

        // For each element of pubKeyCredParams:
        // If the element specifies an algorithm that is supported by the authenticator, and no algorithm has yet been chosen by this loop, then let the algorithm specified by the current element be the chosen algorithm.
        // If the loop completes and no algorithm was chosen then return CTAP2_ERR_UNSUPPORTED_ALGORITHM.
        let algorithm = pub_key_cred_params
            .0
            .iter()
            .filter(|param| param.alg == COSEAlgorithmIdentifier::ES256) // TODO filter other algorithm types
            .next()
            .ok_or(Error::UnsupportedAlgorithm)?;

        // Create a new authenticatorMakeCredential response structure and initialize both its "uv" bit and "up" bit as false.
        let mut uv = false;
        let mut up = false;

        // If the options parameter is present, process all option keys and values present in the parameter.
        // Treat any option keys that are not understood as absent.
        // Note: As the specification defines normative behaviours for the "rk", "up", and "uv" option keys, they MUST be understood by all authenticators.
        // TODO

        // 9. If the enterpriseAttestation parameter is present:
        if enterprise_attestation.is_some() {
            // If the authenticator is not enterprise attestation capable,
            // or the authenticator is enterprise attestation capable but enterprise attestation is disabled,
            // then end the operation by returning CTAP1_ERR_INVALID_PARAMETER.
            return Err(Error::InvalidParameter);
        }

        // 10. If the following statements are all true:
        //   Note: This step allows the authenticator to create a non-discoverable credential without requiring some form of user verification under the below specific criteria.
        //   "rk" and "uv" options are both set to false or omitted.
        //   the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value true.
        //   the pinUvAuthParam parameter is not present.
        //   Then go to Step 12.
        //   Note: Step 4 has already ensured that the "uv" bit is false in the response.
        // TODO

        // 11. If the authenticator is protected by some form of user verification, then:
        //   If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
        if pin_uv_auth_param.is_some() {
            assert_eq!(uv, false);
            // If the authenticator is not protected by pinUvAuthToken,
            // or the authenticator is protected by pinUvAuthToken but pinUvAuthToken is disabled,
            // then end the operation by returning CTAP1_ERR_INVALID_PARAMETER.
            return Err(Error::InvalidParameter);
        }

        // let user_present = self
        //     .presence
        //     .approve_authentication(&application_key.application)
        //     .await?;

        // let application_key = self
        //     .secrets
        //     .retrieve_application_key(&application, &key_handle)?
        //     .ok_or(AuthenticateError::InvalidKeyHandle)?;

        // if !user_present {
        //     return Err(AuthenticateError::ApprovalRequired);
        // }

        // let counter = self
        //     .secrets
        //     .get_and_increment_counter(&application_key.application, &application_key.handle)?;

        // let user_presence_byte = user_presence_byte(user_present);

        // let signature = self.crypto.sign(
        //     application_key.key(),
        //     &message_to_sign_for_authenticate(
        //         &application_key.application,
        //         &challenge,
        //         user_presence_byte,
        //         counter,
        //     ),
        // )?;

        // Ok(Authentication {
        //     counter,
        //     signature,
        //     user_present,
        // })

        todo!()
    }

    fn get_info(&self) -> Result<GetInfoResponse, Error> {
        Ok(self.get_info_internal())
    }
}

impl<Secrets, Crypto, Presence> Service<Command> for Authenticator<Secrets, Crypto, Presence>
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

    fn call(&mut self, command: Command) -> Self::Future {
        // let u2f = Arc::clone(&self.0);
        trace!(?command, "U2fService::call");
        Box::pin(async move {
            match command {
                Command::MakeCredential(MakeCredentialCommand {
                    client_data_hash,
                    rp,
                    user,
                    pub_key_cred_params,
                    exclude_list,
                    extensions,
                    options,
                    pin_uv_auth_param,
                    pin_uv_auth_protocol,
                    enterprise_attestation,
                }) => todo!(),
                Command::GetAssertion {
                    rp_id,
                    client_data_hash,
                } => todo!(),
                Command::GetInfo => {
                    debug!("Get version request");
                    Ok(Response::GetInfo(GetInfoResponse {
                        versions: vec![String::from("FIDO_2_1"), String::from("U2F_V2")],
                        extensions: None,
                        aaguid: AAGUID,
                        options: None,
                        max_msg_size: None,
                        pin_uv_auth_protocols: None,
                        max_credential_count_in_list: None,
                        max_credential_id_length: None,
                        transports: None,
                        algorithms: None,
                        max_serialized_large_blob_array: None,
                        force_pin_change: None,
                        min_pin_length: None,
                        firmware_version: None,
                        max_cred_blob_len: None,
                        max_rp_ids_for_set_min_pin_length: None,
                        preferred_platform_uv_attempts: None,
                        uv_modality: None,
                        certifications: None,
                        remaining_discoverable_credentials: Some(0),
                        vendor_prototype_config_commands: None,
                    }))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{HasPublic, PKeyRef};
    use openssl::sign::Verifier;
    use u2f_core::{
        AppId, ApplicationKey, Attestation, AttestationCertificate, Challenge, Counter, KeyHandle,
        OpenSSLCryptoOperations, PrivateKey,
    };

    use super::*;
    use crate::Signature;

    #[test]
    fn version() {
        let authenticator = fake_authenticator();

        let version = authenticator.version();

        assert_eq!(version.version_major, pkg_version::pkg_version_major!());
        assert_eq!(version.version_minor, pkg_version::pkg_version_minor!());
        assert_eq!(version.version_build, pkg_version::pkg_version_patch!());
        assert_eq!(version.wink_supported, false);
    }

    #[tokio::test]
    async fn get_info_command() {
        let authenticator = fake_authenticator();

        let info = authenticator.get_info().unwrap();

        assert_eq!(info.aaguid, AAGUID);
    }

    fn fake_authenticator(
    ) -> Authenticator<InMemorySecretStore, OpenSSLCryptoOperations, FakeUserPresence> {
        Authenticator::new(
            InMemorySecretStore::new(),
            OpenSSLCryptoOperations::new(fake_attestation()),
            FakeUserPresence::always_approve(),
        )
    }

    fn fake_app_id() -> AppId {
        AppId::from_bytes(&[0u8; 32])
    }

    fn fake_challenge() -> Challenge {
        Challenge::from([0u8; 32])
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

    fn fake_attestation() -> Attestation {
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
