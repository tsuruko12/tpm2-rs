use tss_esapi::{handles::KeyHandle, structures::{Data, RsaDecryptionScheme}};

use crate::{Error, Result, backend::linux::context::CommandResources, types::{LoadedHandle, LoadedObjectHandle, Tpm2bPublicKeyRsa, TpmaSession}};

use super::Context;

impl Context {
    pub(crate) fn wrap_key(
        &mut self, 
        loaded: LoadedHandle, 
        message: Tpm2bPublicKeyRsa,
        session_salt_key: KeyHandle,
    ) -> Result<Tpm2bPublicKeyRsa> {
        let mut resources = CommandResources::default();

        let loaded_handle_is_persistent = loaded.is_persistent();
        resources.add_handle(loaded.handle().into(), loaded_handle_is_persistent);
        resources.add_persistent_handle(session_salt_key.into());

        let result = (|| {
            self.prepare_sessions(
                &mut resources, 
                Some((loaded.handle().into(), loaded.authorization())), 
                TpmaSession::decrypt().with_continue_session(), 
                Some(session_salt_key)
            )?;

            let out_data = self.ctx.execute_with_sessions(resources.session_slots(), |ctx| {
                ctx.rsa_encrypt(
                    loaded.handle(), 
                    message.into(), 
                    RsaDecryptionScheme::Null, 
                    Data::default()
                )
            })
            .map(Into::into)
            .map_err(Error::from_tss_err)?;

            resources.release(self)?;

            Ok(out_data)
        })();

        self.finish_command(result, &mut resources)
    }
}