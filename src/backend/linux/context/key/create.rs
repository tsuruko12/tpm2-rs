use tss_esapi::{
    handles::KeyHandle,
    interface_types::{resource_handles::Hierarchy, session_handles::AuthSession},
    structures::{Auth, Public},
};

use crate::{
    Error, Result, types::{Authorization, CreatedObject, LoadedParent, TpmaSession}
};

use super::Context;
use super::super::CommandResources;

impl Context {
    pub(crate) fn create_and_load(
        &mut self,
        public: &Public,
        auth: Auth,
        parent: &LoadedParent,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        // use password session when session_salt_key is None
        let mut resources = CommandResources::default();
        let parent_handle = parent.handle();

        let result = (|| {
            match session_salt_key {
                Some(_) => {
                    self.prepare_sessions(
                        &mut resources,
                        parent_handle,
                        parent.authorization(),
                        TpmaSession::encrypt_decrypt().with_continue_session(),
                        session_salt_key,
                    )?; 
                },
                None => resources.add_session(AuthSession::Password)?,
            }

            let (out_private, out_public) = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
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
                .map_err(Error::from_tss_err)?;

            match session_salt_key {
                Some(_) => resources.clear_policy_session(),
                None => resources.clear_password_session(),
            }

            let (handle, name) = self.load_handle(
                &out_private,
                &out_public,
                parent,
                session_salt_key,
                Some(&mut resources),
            )?;

            Ok(CreatedObject {
                handle,
                public: out_public.try_into()?,
                private: Some(out_private.value().into()),
                name: name.value().into(),
            })   
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn create_owner_primary(
        &mut self,
        public: &Public,
        owner_authorization: &Authorization,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        let mut resources = CommandResources::default();
        
        let owner_handle = Hierarchy::Owner;
        let session_attrs = match session_salt_key {
            Some(_) => TpmaSession::encrypt_decrypt(),
            None => TpmaSession::empty(),
        };

        let result = (|| {
            self.prepare_sessions(
                &mut resources,
                owner_handle,
                owner_authorization,
                session_attrs,
                session_salt_key,
            )?;

            let (handle, out_public) = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.create_primary(owner_handle, public.clone(), None, None, None, None)
                })
                .map(|created| (created.key_handle, created.out_public))
                .map_err(Error::from_tss_err)?;
            
            resources.add_transient_handle(handle);
            resources.clear_sessions();

            let name = self.ctx.tr_get_name(handle.into()).map_err(Error::esapi)?;

            Ok(CreatedObject {
                handle,
                public: out_public.try_into()?,
                private: None,
                name: name.value().into(),
            })
        })();

        self.finish_command(result, &mut resources)
    }
}
