use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384, Sha512};

use super::Context;
use crate::{
    Error, Key, Result,
    signature::SignatureScheme,
    types::{
        Signature,
        tpm::{Tpm2bDigest, TpmaObject, TpmiAlgHash, TpmiRhHierarchy, TpmtTkHashCheck},
    },
};

// For now, the sign API uses the owner hierarchy when creating a hash validation ticket

impl Context {
    pub fn sign(
        &mut self,
        key: &Key,
        data: &[u8],
        scheme: Option<SignatureScheme>,
    ) -> Result<Signature> {
        let Some(public_area) = self.get_key_public_area(key)? else {
            return Err(Error::invalid_key("invalid key for signing"));
        };

        let mut sig_scheme = public_area.parameters().to_sig_scheme()?;
        let hash_alg = match sig_scheme.details().hash_alg() {
            Some(hash_alg) => hash_alg,
            None => {
                let Some(scheme) = scheme else {
                    return Err(Error::invalid_param(
                        "scheme must be specified for this key",
                    ));
                };
                sig_scheme = scheme.into();

                scheme.hash_alg().into()
            }
        };

        let is_restricted = public_area
            .object_attributes()
            .contains(TpmaObject::RESTRICTED);
        let (digest, validation) = if is_restricted {
            self.backend
                .create_hash_validation_tk(data, hash_alg, TpmiRhHierarchy::OWNER)?
        } else {
            (hash(data, hash_alg)?, TpmtTkHashCheck::null())
        };

        let loaded = self.load_key(key.id())?;
        let session_salt_handle = match self.load_session_salt_handle() {
            Ok(handle) => handle,
            Err(e) => {
                let _ = self.backend.release_handle(loaded.handle);
                return Err(e);
            }
        };

        self.backend
            .sign(loaded, digest, sig_scheme, validation, session_salt_handle)
    }

    pub fn verify_signature(
        &mut self,
        key: &Key,
        data: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        let Some(_) = self.get_key_public_area(key)? else {
            return Err(Error::invalid_key("invalid key for signing"));
        };

        let digest = hash(data, signature.hash_alg().into())?;
        let loaded = self.load_key(key.id())?;

        self.backend.verify_signature(loaded, digest, signature)
    }
}

fn hash(data: &[u8], hash_alg: TpmiAlgHash) -> Result<Tpm2bDigest> {
    match hash_alg {
        TpmiAlgHash::SHA1 => Sha1::digest(data).to_vec().try_into(),
        TpmiAlgHash::SHA256 => Sha256::digest(data).to_vec().try_into(),
        TpmiAlgHash::SHA384 => Sha384::digest(data).to_vec().try_into(),
        TpmiAlgHash::SHA512 => Sha512::digest(data).to_vec().try_into(),
        _ => Err(Error::invalid_state(
            "unexpected hash algorithm in signature scheme",
        )),
    }
}
