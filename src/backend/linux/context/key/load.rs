use tss_esapi::{
    handles::{ObjectHandle, PersistentTpmHandle},
    structures::{Private, Public},
};

use super::{CommandResources, Context, read_public::validate_obj_name};
use crate::{
    Error, Result,
    backend::linux::context::key::compute_obj_name,
    db::InternalKeyMeta,
    types::{
        Authorization, LoadedHandle, LoadedObjectHandle,
        tpm::{
            Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmaSession, TpmiDhPersistent, TpmiRhHierarchy,
        },
    },
};

impl Context {
    pub(super) fn load_handle(
        &mut self,
        in_private: Private,
        in_public: Public,
        parent: &LoadedHandle,
        session_salt_handle: Option<ObjectHandle>,
        caller_resources: Option<&mut CommandResources>,
    ) -> Result<(LoadedObjectHandle, Tpm2bName)> {
        let parent_handle = parent.handle.inner();
        let session_attrs = match session_salt_handle {
            Some(_) => TpmaSession::decrypt(),
            None => TpmaSession::empty(),
        };

        let mut default_resources = CommandResources::default();
        let resources = caller_resources.unwrap_or(&mut default_resources);

        let result = (|| {
            self.prepare_sessions(
                resources,
                session_attrs,
                Some((parent_handle, &parent.authorization)),
                session_salt_handle.map(Into::into),
            )?;

            let obj_handle = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.load(parent_handle.into(), in_private, in_public.clone())
                })
                .map_err(Error::from_tss_err)?;
            resources.add_transient_handle(obj_handle.into());

            let name = compute_obj_name(&in_public)?;

            Ok((LoadedObjectHandle::Transient(obj_handle.into()), name))
        })();

        self.finalize_command(result, resources)
    }

    pub(crate) fn resolve_persistent_handle(
        &mut self,
        persistent_handle: TpmiDhPersistent,
        expected_name: &Tpm2bName,
    ) -> Result<LoadedObjectHandle> {
        let obj_handle =
            self.load_persistent_handle(persistent_handle)?;

        let mut resources = CommandResources::default();

        let result = (|| {
            let name = self.read_obj_name(obj_handle.inner().into())?;
            validate_obj_name(name.as_bytes(), expected_name.as_bytes())?;

            Ok(obj_handle)
        })();

        self.finalize_command(result, &mut resources)
    }

    pub(crate) fn resolve_internal_key(
        &mut self,
        key_meta: InternalKeyMeta,
    ) -> Result<LoadedHandle> {
        let obj_handle = self
            .load_persistent_handle(key_meta.handle)
            .map(|handle| handle.inner())?;

        let mut resources = CommandResources::default();

        let result = (|| {
            let name = self.read_obj_name(obj_handle.into())?;
            validate_obj_name(name.as_bytes(), key_meta.obj_name.as_bytes())?;

            Ok(LoadedHandle::internal_persistent(
                obj_handle,
                key_meta.obj_name,
            ))
        })();

        self.finalize_command(result, &mut resources)
    }

    pub(crate) fn load_persistent_handle(
        &mut self,
        persistent_handle: TpmiDhPersistent,
    ) -> Result<LoadedObjectHandle> {
        self.ctx
            .tr_from_tpm_public(PersistentTpmHandle::from(persistent_handle).into())
            .map(LoadedObjectHandle::Persistent)
            .map_err(Error::esapi)
    }

    pub(crate) fn load_temporary_key(
        &mut self,
        private: Tpm2bPrivate,
        public: Tpm2bPublic,
        authorization: Authorization,
        parent: LoadedHandle,
        session_salt_handle: ObjectHandle,
        expected_name: &Tpm2bName,
    ) -> Result<LoadedHandle> {
        let public = public.try_into()?;

        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle);
        resources.add_handle(parent.handle);

        let result = (|| {
            let (obj_handle, obj_name) = self.load_handle(
                private.into(),
                public,
                &parent,
                Some(session_salt_handle),
                Some(&mut resources),
            )?;
            resources.close_handle(self, session_salt_handle)?;
            resources.release_handle(self, parent.handle)?;

            validate_obj_name(obj_name.as_bytes(), expected_name.as_bytes())?;

            Ok(LoadedHandle::new(obj_handle, obj_name, authorization))
        })();

        self.finalize_command(result, &mut resources)
    }

    pub(crate) fn load_primary_key(
        &mut self,
        primary_handle: TpmiRhHierarchy,
        public: Tpm2bPublic,
        authorization: Authorization,
        primary_authorization: &Authorization,
        session_salt_handle: ObjectHandle,
        expected_name: &Tpm2bName,
    ) -> Result<LoadedHandle> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle);

        let result = (|| {
            let created = self.create_primary(
                primary_handle,
                public,
                authorization.auth.clone(),
                primary_authorization,
                Some(session_salt_handle),
            )?;
            resources.add_transient_handle(created.handle);
            resources.close_all_handles(self)?;

            validate_obj_name(created.name.as_bytes(), expected_name.as_bytes())?;

            Ok(LoadedHandle::transient(
                created.handle,
                created.name,
                authorization,
            ))
        })();

        self.finalize_command(result, &mut resources)
    }
}
