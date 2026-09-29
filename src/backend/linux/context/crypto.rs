use tss_esapi::{
    handles::ObjectHandle,
    structures::{HashcheckTicket, MaxBuffer, SignatureScheme as EsapiSignatureScheme},
};

use super::{CommandResources, Context};
use crate::{
    Error, Result,
    types::{
        LoadedHandle, Signature,
        tpm::{
            Tpm2bDigest, TpmaSession, TpmiAlgHash, TpmiRhHierarchy, TpmtSigScheme, TpmtTkHashCheck,
        },
    },
};

impl Context {
    pub(crate) fn sign(
        &mut self,
        loaded: LoadedHandle,
        digest: Tpm2bDigest,
        in_scheme: TpmtSigScheme,
        validation: TpmtTkHashCheck,
        session_salt_handle: ObjectHandle,
    ) -> Result<Signature> {
        let obj_handle = loaded.handle.inner();

        let mut resources = CommandResources::default();
        resources.add_handle(loaded.handle);
        resources.add_persistent_handle(session_salt_handle);

        let result = (|| {
            let in_scheme = EsapiSignatureScheme::try_from(in_scheme)?;
            let validation = HashcheckTicket::try_from(validation)?;

            self.prepare_sessions(
                &mut resources,
                TpmaSession::empty(),
                Some((obj_handle, &loaded.authorization)),
                Some(session_salt_handle.into()),
            )?;

            let signature = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.sign(obj_handle.into(), digest.into(), in_scheme, validation)
                })
                .map_err(Error::from_tss_err)?;

            Signature::try_from(signature)
        })();

        self.finalize_command(result, &mut resources)
    }

    pub(crate) fn create_hash_validation_tk(
        &mut self,
        data: &[u8],
        hash_alg: TpmiAlgHash,
        hierarchy: TpmiRhHierarchy,
    ) -> Result<(Tpm2bDigest, TpmtTkHashCheck)> {
        if data.len() > MaxBuffer::MAX_SIZE {
            return Err(Error::invalid_param(format!(
                "data size must not exceed {} bytes",
                MaxBuffer::MAX_SIZE,
            )));
        }

        let (out_hash, validation) = self
            .ctx
            .hash(
                data.try_into()
                    .expect("data must not exceed MaxBuffer::MAX_SIZE"),
                hash_alg.try_into()?,
                hierarchy.try_into()?,
            )
            .map_err(Error::from_tss_err)?;

        Ok((out_hash.into(), validation.try_into()?))
    }
}
