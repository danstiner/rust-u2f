use std::sync::Mutex;

use async_trait::async_trait;
use fido2_api::{
    Aaguid, AttestationCertificate, AttestationStatement, AttestedCredentialData,
    AuthenticatorData, PackedAttestationStatement, PublicKeyCredentialDescriptor,
    RelyingPartyIdentifier, Sha256,
};

use crate::{
    authenticator::CredentialHandle,
    crypto::{PrivateKeyCredentialSource, PublicKeyCredentialSource},
    CredentialProtection, SecretStore,
};

pub trait SecretStoreActual {
    type Error;

    fn put_discoverable(
        &mut self,
        credential: PrivateKeyCredentialSource,
    ) -> Result<(), Self::Error>;

    fn get(
        &self,
        credential_handle: &CredentialHandle,
    ) -> Result<Option<PrivateKeyCredentialSource>, Self::Error>;

    fn list_discoverable(
        &self,
        rp_id: &RelyingPartyIdentifier,
    ) -> Result<Vec<CredentialHandle>, Self::Error>;
}

pub struct SimpleSecrets<S>(Mutex<SimpleSecretsData<S>>);

impl<S> SimpleSecrets<S> {
    pub fn new(store: S, aaguid: Aaguid) -> Self {
        Self(Mutex::new(SimpleSecretsData {
            aaguid,
            rng: ring::rand::SystemRandom::new(),
            store,
        }))
    }
}

pub(crate) struct SimpleSecretsData<S> {
    aaguid: Aaguid,
    rng: ring::rand::SystemRandom,
    store: S,
}

#[async_trait(?Send)]
impl<S: SecretStoreActual> SecretStore for SimpleSecrets<S> {
    type Error = S::Error;

    async fn make_credential(
        &self,
        pub_key_cred_params: &fido2_api::PublicKeyCredentialParameters,
        rp_id: &fido2_api::RelyingPartyIdentifier,
        user_handle: &fido2_api::UserHandle,
    ) -> Result<CredentialHandle, Self::Error> {
        let mut data = self.0.lock().unwrap();
        let key = PrivateKeyCredentialSource::generate(
            &pub_key_cred_params.alg,
            &pub_key_cred_params.type_,
            rp_id,
            user_handle,
            &data.rng,
        )
        .unwrap();
        let descriptor = PublicKeyCredentialDescriptor {
            type_: key.type_.clone(),
            id: key.id.clone(),
        };
        data.store.put_discoverable(key)?;
        Ok(CredentialHandle {
            descriptor,
            protection: CredentialProtection {
                is_user_verification_required: false,
                is_user_verification_optional_with_credential_id_list: false,
            },
            rp_id: rp_id.clone(),
        })
    }

    async fn attest(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
        credential_handle: &CredentialHandle,
        client_data_hash: &fido2_api::Sha256,
        user_present: bool,
        user_verified: bool,
    ) -> Result<(AuthenticatorData, AttestationStatement), Self::Error> {
        let data = self.0.lock().unwrap();
        if let Some(key) = data.store.get(credential_handle)? {
            let key: PublicKeyCredentialSource = key.try_into().unwrap();
            let auth_data = AuthenticatorData {
                rp_id_hash: Sha256::digest(rp_id.as_bytes()),
                user_present,
                user_verified,
                sign_count: 1,
                attested_credential_data: Some(vec![AttestedCredentialData {
                    aaguid: data.aaguid,
                    credential_id: credential_handle.descriptor.id.clone(),
                    credential_public_key: key.credential_public_key(),
                }]),
            };
            // TODO increment use counter
            let signature = key.sign(&auth_data, client_data_hash, &data.rng).unwrap();
            Ok((
                auth_data,
                AttestationStatement::Packed(PackedAttestationStatement {
                    alg: key.alg(),
                    sig: signature,
                    x5c: Some(AttestationCertificate {
                        attestation_certificate: key.public_key_document().as_ref().to_vec(), // TODO this should be the authenticator's certificate
                        ca_certificate_chain: vec![],
                    }),
                }),
            ))
        } else {
            todo!("error")
        }
    }

    async fn assert(
        &self,
        rp_id: &RelyingPartyIdentifier,
        credential_handle: &CredentialHandle,
        client_data_hash: &Sha256,
        user_present: bool,
        user_verified: bool,
    ) -> Result<(AuthenticatorData, fido2_api::Signature), Self::Error> {
        let data = self.0.lock().unwrap();
        if let Some(key) = data.store.get(credential_handle)? {
            let key: PublicKeyCredentialSource = key.try_into().unwrap();
            let auth_data = AuthenticatorData {
                rp_id_hash: Sha256::digest(rp_id.as_bytes()),
                user_present,
                user_verified,
                sign_count: 2,
                attested_credential_data: None,
            };
            // TODO increment use counter
            let signature = key.sign(&auth_data, client_data_hash, &data.rng).unwrap();
            Ok((auth_data, signature))
        } else {
            todo!("error")
        }
    }

    async fn list_discoverable_credentials(
        &self,
        rp_id: &RelyingPartyIdentifier,
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        let data = self.0.lock().unwrap();
        data.store.list_discoverable(rp_id)
    }

    async fn list_specified_credentials(
        &self,
        _rp_id: &RelyingPartyIdentifier,
        _credential_list: &[PublicKeyCredentialDescriptor],
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        todo!()
    }
}
