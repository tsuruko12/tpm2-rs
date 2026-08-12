use tss_esapi::{
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle as EsapiTpmHandle},
    interface_types::session_handles::AuthSession,
    structures::{Private, Public},
};

use crate::{
    Error, Result, 
    db::InternalKeyMeta, 
    types::{
        Authorization, HandleResource, LoadedHandle, LoadedObjectHandle, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmaSession, TpmiDhPersistent, TpmiRhHierarchy
    }
};
use super::Context;
use super::super::CommandResources;

impl Context {
    pub(super) fn load_handle(
        &mut self,
        in_private: Private,
        in_public: Public,
        parent: &LoadedHandle,
        session_salt_key: Option<KeyHandle>,
        caller_resources: Option<&mut CommandResources>,
    ) -> Result<(LoadedObjectHandle, Tpm2bName)> {
        let mut default_resources = CommandResources::default();
        let resources = caller_resources.unwrap_or(&mut default_resources);

        let parent_handle = parent.handle();

        let result = (|| {
            match session_salt_key {
                Some(_) => {
                    self.prepare_sessions(
                        resources, 
                        Some((parent_handle.into(), parent.authorization())),
                        TpmaSession::decrypt().with_continue_session(), 
                        session_salt_key,
                    )?
                },
                None => resources.add_session(AuthSession::Password)?,
            }

            let obj_handle = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.load(parent_handle, in_private, in_public)
                })
                .map_err(Error::from_tss_err)?;
            
            resources.flush_policy_session(self)?;
            resources.add_transient_handle(obj_handle.into());

            Ok((obj_handle, self.read_obj_name(obj_handle.into())?))
        })();

        self.finish_command(result, resources)
    }

    pub(crate) fn resolve_persistent_handle(
        &mut self, 
        persistent_handle: TpmiDhPersistent,
        obj_name: &Tpm2bName,
    ) -> Result<ObjectHandle> {
        let mut obj_handle = self
            .load_persistent_handle(PersistentTpmHandle::from(persistent_handle).into())?;

        match self.validate_obj_name(obj_handle, obj_name, None) {
            Ok(()) => Ok(obj_handle),
            Err(e) => {
                let _ = self.close_handle(&mut obj_handle);
                Err(e)
            }
        }
    }
    
    pub(crate) fn resolve_internal_key(&mut self, key_meta: InternalKeyMeta) -> Result<LoadedHandle> {
        let mut obj_handle = self
            .load_persistent_handle(PersistentTpmHandle::from(key_meta.handle).into())?;

        match self.validate_obj_name(obj_handle, &key_meta.obj_name, None) {
            Ok(()) => Ok(LoadedHandle::internal_persistent(
                obj_handle.into(), 
                key_meta.obj_name,
            )),
            Err(e) => {
                let _ = self.close_handle(&mut obj_handle);
                Err(e)
            }
        }
    }

    pub(crate) fn load_persistent_handle(
        &mut self,
        tpm_handle: EsapiTpmHandle,
    ) -> Result<ObjectHandle> {
        self.ctx
            .tr_from_tpm_public(tpm_handle)
            .map_err(Error::esapi)
    }

    pub(crate) fn load_temporary_key(
        &mut self, 
        private: Tpm2bPrivate,
        public: Tpm2bPublic,
        authorization: Authorization,
        parent: LoadedHandle,
        session_salt_key: LoadedObjectHandle,
        expected_name: &Tpm2bName,
    ) -> Result<LoadedHandle> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_key.into());

        let parent_is_persistent = parent.is_persistent();
        resources.add_handle(parent.handle().into(), parent_is_persistent);

        let result = (|| {
            let (obj_handle, obj_name) = self.load_handle(
                private.into(), 
                public.try_into()?, 
                &parent, 
                Some(session_salt_key), 
                Some(&mut resources)
            )?;

            resources.close_handle(self, session_salt_key.into())?;
            resources.release_handle(self, parent.handle().into(), parent_is_persistent)?;

            self.validate_obj_name(obj_handle.into(), expected_name, Some(&obj_name))?;

            Ok(LoadedHandle::transient(
                obj_handle, 
                obj_name, 
                authorization
            ))
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn load_primary_key(
        &mut self,
        primary_handle: TpmiRhHierarchy,
        public: Tpm2bPublic,
        authorization: Authorization,
        primary_authorization: &Authorization,
        session_salt_key: LoadedObjectHandle,
        expected_name: &Tpm2bName,
    ) -> Result<LoadedHandle> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_key.into());

        let result = (|| {
            let created = self.create_primary(
                primary_handle, 
                public, 
                authorization.auth().duplicate(),
                primary_authorization, 
                Some(session_salt_key)
            )?;

            resources.add_transient_handle(created.handle.into());
            resources.close_handle(self, session_salt_key.into())?;

            self.validate_obj_name(created.handle.into(), expected_name, Some(&created.name))?;

            Ok(LoadedHandle::transient(
                created.handle, 
                created.name,
                authorization
            ))
        })();

        self.finish_command(result, &mut resources)
    }
}
