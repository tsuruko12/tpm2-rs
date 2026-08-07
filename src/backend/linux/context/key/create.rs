use tss_esapi::{
    handles::KeyHandle,
    interface_types::{resource_handles::Hierarchy, session_handles::AuthSession},
    structures::{Auth, Public},
};

use crate::{
    Error, Result, types::{Authorization, CreatedObject, LoadedParent, TpmaSession, TpmtPublic}
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
                        Some((parent_handle.into(), parent.authorization())),
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

            let (obj_handle, name) = self.load_handle(
                &out_private,
                &out_public,
                parent,
                session_salt_key,
                Some(&mut resources),
            )?;

            Ok(CreatedObject {
                obj_handle,
                public: TpmtPublic::try_from(out_public)?.into(),
                private: Some(out_private.value().into()),
                name: name.try_into()?,
            })   
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn create_owner_primary(
        &mut self,
        in_public: &Public,
        owner_authorization: &Authorization,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        let mut resources = CommandResources::default();
        
        let primary_handle = Hierarchy::Owner;
        let session_attrs = match session_salt_key {
            Some(_) => TpmaSession::encrypt_decrypt(),
            None => TpmaSession::empty(),
        };

        let result = (|| {
            self.prepare_sessions(
                &mut resources,
                Some((primary_handle.into(), owner_authorization)),
                session_attrs,
                session_salt_key,
            )?;

            let (obj_handle, out_public) = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.create_primary(primary_handle, in_public.clone(), None, None, None, None)
                })
                .map(|created| (created.key_handle, created.out_public))
                .map_err(Error::from_tss_err)?;
            
            resources.add_transient_handle(obj_handle);
            resources.clear_sessions();

            let name = self.read_object_name(obj_handle)?;

            Ok(CreatedObject {
                obj_handle,
                public: TpmtPublic::try_from(out_public)?.into(),
                private: None,
                name: name.try_into()?,
            })
        })();

        self.finish_command(result, &mut resources)
    }
}
