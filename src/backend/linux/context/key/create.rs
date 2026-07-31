use tss_esapi::{
    handles::KeyHandle,
    interface_types::resource_handles::Hierarchy,
    structures::{Auth, Public},
};

use crate::{
    Error, Result,
    types::{Authorization, CreatedObject, LoadedParent, TpmaSession},
};

use super::Context;

impl Context {
    pub(crate) fn create_and_load(
        &mut self,
        public: &Public,
        auth: Auth,
        parent: &LoadedParent,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        let parent_handle = parent.handle();

        let sessions = self.prepare_sessions(
            parent_handle,
            parent.authorization(),
            TpmaSession::encrypt_decrypt().with_continue_session(),
            session_salt_key,
        )?;

        let result = self
            .ctx
            .execute_with_sessions(sessions, |ctx| {
                ctx.create(
                    parent_handle,
                    public.clone().into(),
                    Some(auth),
                    None,
                    None,
                    None,
                )
            })
            .map(|created| (created.out_private, created.out_public))
            .map_err(Error::from_tss_err);

        let (out_private, out_public) = match result {
            Ok((private, public)) => (private, public),
            Err(e) => {
                let _ = self.flush_sessions();
                return Err(e);
            }
        };

        self.clear_policy_session();

        let (handle, name) = self.load_handle(
            &out_private,
            &out_public,
            parent,
            session_salt_key,
            self.find_hmac_session(),
        )?;

        Ok(CreatedObject {
            handle,
            public: out_public.try_into()?,
            private: Some(out_private.value().into()),
            name: name.value().into(),
        })
    }

    pub(crate) fn create_owner_primary(
        &mut self,
        public: &Public,
        owner_authorization: &Authorization,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        let owner_handle = Hierarchy::Owner;

        let sessions = self.prepare_sessions(
            owner_handle,
            owner_authorization,
            TpmaSession::encrypt_decrypt(),
            session_salt_key,
        )?;

        let (handle, out_public) = self
            .ctx
            .execute_with_sessions(sessions, |ctx| {
                ctx.create_primary(owner_handle, public.clone(), None, None, None, None)
            })
            .map(|created| (created.key_handle, created.out_public))
            .map_err(Error::from_tss_err)?;

        self.clear_sessions();

        let name = self.ctx.tr_get_name(handle.into()).map_err(Error::esapi)?;

        Ok(CreatedObject {
            handle: handle,
            public: out_public.try_into()?,
            private: None,
            name: name.value().into(),
        })
    }
}
