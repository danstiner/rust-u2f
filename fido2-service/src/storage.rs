use crate::{
    authenticator::CredentialHandle,
    crypto::{PrivateKeyCredentialSource, PublicKeyCredentialSource},
    CredentialStore,
};
use async_trait::async_trait;
use fido2_api::{
    Aaguid, AttestationStatement, AttestedCredentialData, AuthenticatorData,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialRpEntity,
    RelyingPartyIdentifier, Sha256, Signature, UserHandle,
};
use std::sync::Mutex;

pub trait CredentialStorage {
    type Error;

    fn put_discoverable(
        &mut self,
        credential: PrivateKeyCredentialSource,
    ) -> Result<(), Self::Error>;

    fn put_specific(&mut self, credential: PrivateKeyCredentialSource) -> Result<(), Self::Error>;

    fn get_and_increment_sign_count(
        &mut self,
        credential_handle: &CredentialHandle,
    ) -> Result<Option<PrivateKeyCredentialSource>, Self::Error>;

    fn list_discoverable(
        &self,
        rp_id: &RelyingPartyIdentifier,
    ) -> Result<Vec<CredentialHandle>, Self::Error>;

    fn list_specified(
        &self,
        rp_id: &RelyingPartyIdentifier,
        credential_list: &[PublicKeyCredentialDescriptor],
    ) -> Result<Vec<CredentialHandle>, Self::Error>;
}

pub struct SoftwareCryptoStore<S>(Mutex<Data<S>>);

impl<S> SoftwareCryptoStore<S> {
    pub fn new(store: S, aaguid: Aaguid, rng: ring::rand::SystemRandom) -> Self {
        Self(Mutex::new(Data { aaguid, rng, store }))
    }
}

pub(crate) struct Data<S> {
    aaguid: Aaguid,
    rng: ring::rand::SystemRandom,
    store: S,
}

#[async_trait(?Send)]
impl<S: CredentialStorage> CredentialStore for SoftwareCryptoStore<S>
where
    S: CredentialStorage,
    S::Error: From<ring::error::Unspecified>,
{
    type Error = S::Error;

    async fn make_credential(
        &self,
        parameters: &PublicKeyCredentialParameters,
        rp: &PublicKeyCredentialRpEntity,
        user_handle: &UserHandle,
        discoverable: bool,
    ) -> Result<CredentialHandle, Self::Error> {
        let mut this = self.0.lock().unwrap();
        let key = PrivateKeyCredentialSource::generate(parameters, rp, user_handle, &this.rng)?;
        let handle = key.handle();
        if discoverable {
            this.store.put_discoverable(key)?;
        } else {
            this.store.put_specific(key)?;
        }
        Ok(handle)
    }

    async fn attest(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
        credential_handle: &CredentialHandle,
        _client_data_hash: &fido2_api::Sha256,
        user_present: bool,
        user_verified: bool,
    ) -> Result<(AuthenticatorData, AttestationStatement), Self::Error> {
        let mut this = self.0.lock().unwrap();
        if let Some(key) = this.store.get_and_increment_sign_count(credential_handle)? {
            let sign_count = key.sign_count;
            let key: PublicKeyCredentialSource = key.try_into().unwrap();
            let auth_data = AuthenticatorData {
                rp_id_hash: Sha256::digest(rp_id.as_bytes()),
                user_present,
                user_verified,
                sign_count,
                attested_credential_data: Some(vec![AttestedCredentialData {
                    aaguid: this.aaguid,
                    credential_id: credential_handle.descriptor.id.clone(),
                    credential_public_key: key.credential_public_key(),
                }]),
            };
            Ok((auth_data, AttestationStatement::None))
        } else {
            todo!("error")
        }
    }

    async fn assert(
        &self,
        _rp_id: &RelyingPartyIdentifier,
        credential_handle: &CredentialHandle,
        client_data_hash: &Sha256,
        user_present: bool,
        user_verified: bool,
    ) -> Result<(AuthenticatorData, Signature), Self::Error> {
        let mut this = self.0.lock().unwrap();
        if let Some(key) = this.store.get_and_increment_sign_count(credential_handle)? {
            let sign_count = key.sign_count;
            let key: PublicKeyCredentialSource = key.try_into().unwrap();
            let auth_data = AuthenticatorData {
                rp_id_hash: Sha256::digest(credential_handle.rp.id.as_bytes()),
                user_present,
                user_verified,
                sign_count: sign_count,
                attested_credential_data: None,
            };
            let signature = key.sign(&auth_data, client_data_hash, &this.rng).unwrap();
            Ok((auth_data, signature))
        } else {
            todo!("error")
        }
    }

    async fn list_discoverable_credentials(
        &self,
        rp_id: &RelyingPartyIdentifier,
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        let this = self.0.lock().unwrap();
        this.store.list_discoverable(rp_id)
    }

    async fn list_specified_credentials(
        &self,
        rp_id: &RelyingPartyIdentifier,
        credential_list: &[PublicKeyCredentialDescriptor],
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        let this = self.0.lock().unwrap();
        this.store.list_specified(rp_id, credential_list)
    }

    fn list_supported_algorithms(&self) -> Vec<PublicKeyCredentialParameters> {
        vec![PublicKeyCredentialParameters::es256()]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pass() {}
}
