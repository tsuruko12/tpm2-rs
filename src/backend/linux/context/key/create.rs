use tss_esapi::{
    handles::KeyHandle,
    interface_types::{resource_handles::Hierarchy as EsapiHierarchy, session_handles::AuthSession},
    structures::Public,
};

use crate::{
    Error, Result, db::{KeyMeta, TpmKeyMeta}, hierarchy::Hierarchy, public::KeyTemplate, types::{
        Authorization, CreatedObject, Key, LoadedHandle, PolicyData, Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, TpmaSession, TpmiRhHierarchy
    }
};

use super::Context;
use super::super::CommandResources;

impl Context {
    pub(crate) fn create_child_key(
        &mut self,
        in_public: Tpm2bPublic,
        auth: Tpm2bAuth,
        parent: LoadedHandle,
        session_salt_key: KeyHandle,
    ) -> Result<CreatedObject> {
        let mut resources = CommandResources::default();

        let parent_is_persistent = parent.is_persistent();
        resources.add_handle(parent.handle().into(), parent_is_persistent);

        let result = (|| {
            let created = self.create_and_load(
                in_public, 
                auth, 
                &parent, 
                Some(session_salt_key)
            )?;

            resources.add_transient_handle(created.handle.into());
            resources.release(self)?;

            Ok(created)
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn create_srk(
        &mut self, 
        in_public: Tpm2bPublic,
        auth: Tpm2bAuth,
        owner_authorization: &Authorization,
        session_salt_key: KeyHandle,
    ) -> Result<CreatedObject> {
        let created = self.create_primary(
            TpmiRhHierarchy::OWNER, 
            in_public, 
            auth, 
            owner_authorization, 
            Some(session_salt_key)
        )?;      
        self.flush_handle(&mut created.handle.into())?;

        Ok(created)
    }

    pub(crate) fn create_and_load(
        &mut self,
        in_public: Tpm2bPublic,
        auth: Tpm2bAuth,
        parent: &LoadedHandle,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        // use password session when session_salt_key is None
        let mut resources = CommandResources::default();

        let in_public = Public::try_from(in_public)?;
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
                        in_public,
                        Some(auth.into()),
                        None,
                        None,
                        None,
                    )
                })
                .map(|created| (created.out_private, created.out_public))
                .map_err(Error::from_tss_err)?;

            match session_salt_key {
                Some(_) => resources.flush_policy_session(self)?,
                None => resources.clear_password_session(),
            }

            let (handle, name) = self.load_handle(
                out_private.clone(),
                out_public.clone(),
                parent,
                session_salt_key,
                Some(&mut resources),
            )?;

            Ok(CreatedObject {
                handle,
                public: out_public.try_into()?,
                private: Some(out_private.into()),
                name,
            })   
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn create_primary(
        &mut self,
        primary_handle: TpmiRhHierarchy,
        in_public: Tpm2bPublic,
        auth: Tpm2bAuth,
        primary_authorization: &Authorization,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        let mut resources = CommandResources::default();
        
        let in_public = Public::try_from(in_public)?;
        let primary_handle = EsapiHierarchy::try_from(primary_handle)
            .map_err(|_| Error::invalid_state("unexpected primary hierarchy"))?;
        let session_attrs = match session_salt_key {
            Some(_) => TpmaSession::encrypt_decrypt().with_continue_session(),
            None => TpmaSession::continue_session(),
        };

        let result = (|| {
            self.prepare_sessions(
                &mut resources,
                Some((primary_handle.into(), primary_authorization)),
                session_attrs,
                session_salt_key,
            )?;

            let (handle, out_public) = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.create_primary(
                        primary_handle, 
                        in_public, 
                        Some(auth.into()), 
                        None, 
                        None, 
                        None,
                    )
                })
                .map(|created| (created.key_handle, created.out_public))
                .map_err(Error::from_tss_err)?;
            
            resources.add_transient_handle(handle.into());

            Ok(CreatedObject {
                handle,
                public: out_public.try_into()?,
                private: None,
                name: self.read_obj_name(handle.into())?,
            })
        })();

        self.finish_command(result, &mut resources)
    }
}
