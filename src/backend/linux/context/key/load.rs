use tss_esapi::{
    handles::{KeyHandle, ObjectHandle, TpmHandle as EsapiTpmHandle},
    interface_types::session_handles::AuthSession,
    structures::{Name, Private, Public},
};

use super::Context;
use crate::{
    Error, Result,
    types::{LoadedParent, TpmaSession},
};

impl Context {
    pub(super) fn load_handle(
        &mut self,
        private: &Private,
        public: &Public,
        parent: &LoadedParent,
        session_salt_key: Option<KeyHandle>,
        hmac_session: Option<AuthSession>,
    ) -> Result<(KeyHandle, Name)> {
        let parent_handle = parent.handle();
        let parent_authorization = parent.authorization();

        // memo: set continue_sessions to normarize from create_and_load
        let session_attrs = TpmaSession::decrypt();
        let sessions = match hmac_session {
            Some(hmac) => {
                self.prepare_sessions_with_hmac(
                    hmac,
                    session_attrs,
                    parent_authorization.policy(),
                    session_salt_key,
                )?
            },
            None => {
                self.prepare_sessions(
                    parent_handle,
                    parent_authorization,
                    session_attrs,
                    session_salt_key,
                )?
            },
        };

        let result = self
            .ctx
            .execute_with_sessions(sessions, |ctx| {
                ctx.load(parent_handle, private.clone(), public.clone())
            })
            .map_err(Error::from_tss_err);

        match result {
            Ok(handle) => {
                self.clear_sessions();
                Ok((handle, self.read_object_name(handle)?))
            }
            Err(e) => {
                let _ = self.flush_sessions();
                Err(e)
            }
        }
    }

    pub(crate) fn load_tpm_handle(
        &mut self,
        tpm_handle: impl Into<EsapiTpmHandle>,
    ) -> Result<ObjectHandle> {
        self.ctx
            .tr_from_tpm_public(tpm_handle.into())
            .map_err(Error::esapi)
    }
}
