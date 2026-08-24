use tss_esapi::{handles::KeyHandle, structures::{Data, RsaDecryptionScheme}};

use crate::{
    Error, Result, 
    types::{Authorization, LoadedObjectHandle, tpm::{Tpm2bPublicKeyRsa, TpmaSession}}};
use super::{Context, CommandResources};

impl Context {
    pub(super) fn wrap_key(
        &mut self, 
        rsa_handle: LoadedObjectHandle, 
        rsa_authorization: &Authorization,
        message: Tpm2bPublicKeyRsa,
        session_salt_handle: KeyHandle,
    ) -> Result<Tpm2bPublicKeyRsa> {
        let mut resources = CommandResources::default();

        let result = (|| {
            self.prepare_sessions(
                &mut resources, 
                TpmaSession::decrypt().with_continue_session(), 
                Some((rsa_handle.inner().into(), rsa_authorization)), 
                Some(session_salt_handle)
            )?;

            self.ctx.execute_with_sessions(resources.session_slots(), |ctx| {
                ctx.rsa_encrypt(
                    rsa_handle.inner(), 
                    message.into(), 
                    RsaDecryptionScheme::Oaep, 
                    Data::default()
                )
            })
            .map(Into::into)
            .map_err(Error::from_tss_err)
        })();

        self.finish_command(result, &mut resources)
    }
}
