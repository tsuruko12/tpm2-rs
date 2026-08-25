use super::{
    Command, CommandResources, Context, 
    read_public::validate_obj_name,
};
use super::super::LoadResponse;
use crate::{
    Result,
    db::InternalKeyMeta,
    types::{
        Authorization, LoadedHandle, LoadedObjectHandle,
        tpm::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmCc, TpmMarshal, TpmaSession,
            TpmiDhObject, TpmiDhPersistent, TpmiRhHierarchy},
    },
};

const RESPONSE_HANDLE_COUNT: usize = 1;

impl Context {
    pub(super) fn load_handle(
        &mut self,
        in_private: &Tpm2bPrivate,
        in_public: &Tpm2bPublic,
        parent: &LoadedHandle,
        session_salt_handle: Option<TpmiDhObject>,
        caller_resources: Option<&mut CommandResources>,
    ) -> Result<(LoadedObjectHandle, Tpm2bName)> {
        let mut command_params = Vec::new();
        in_private.marshal(&mut command_params)?;
        in_public.marshal(&mut command_params)?;

        let mut default_resources = CommandResources::default();
        let resources = caller_resources.unwrap_or(&mut default_resources);

        let result = (|| {
            let session_attrs = match session_salt_handle {
                Some(_) => TpmaSession::encrypt_decrypt(),
                None => TpmaSession::empty(),
            };
            let authorization_area = self.prepare_sessions(
                resources,
                session_attrs,
                Some(&parent.authorization),
                session_salt_handle,
            )?;
            
            let mut command = Command::new(TpmCc::LOAD)
                .with_handles([parent.handle.inner()])
                .with_authorization_area(authorization_area)
                .with_parameters(&mut command_params);

            let response_body = self.submit(&mut command, RESPONSE_HANDLE_COUNT, resources)?;
            let response = LoadResponse::try_from(response_body)?;

            Ok((
                LoadedObjectHandle::Transient(
                    response
                        .object_handle
                        .try_into()
                        .expect("loaded handle must be transient"),
                ),
                response.name,
            ))
        })();

        self.cleanup_on_error(result, resources)
    }

    pub(crate) fn resolve_persistent_handle(
        &mut self,
        persistent_handle: TpmiDhPersistent,
        expected_name: &Tpm2bName,
    ) -> Result<LoadedObjectHandle> {
        let obj_handle = LoadedObjectHandle::Persistent(persistent_handle.into());
        let name = self.read_obj_name(obj_handle.inner())?;
        validate_obj_name(name.as_bytes(), expected_name.as_bytes())?;

        Ok(obj_handle)
    }

    pub(crate) fn resolve_internal_key(
        &mut self,
        key_meta: InternalKeyMeta,
    ) -> Result<LoadedHandle> {
        let obj_handle = LoadedObjectHandle::Persistent(key_meta.handle.into());
        let name = self.read_obj_name(obj_handle.inner())?;
        validate_obj_name(name.as_bytes(), key_meta.obj_name.as_bytes())?;

        Ok(LoadedHandle::internal_persistent(
            key_meta.handle.into(),
            key_meta.obj_name,
        ))
    }

    pub(crate) fn load_temporary_key(
        &mut self,
        private: Tpm2bPrivate,
        public: Tpm2bPublic,
        authorization: Authorization,
        parent: LoadedHandle,
        session_salt_handle: TpmiDhObject,
        expected_name: &Tpm2bName,
    ) -> Result<LoadedHandle> {
        let mut resources = CommandResources::default();
        resources.track_loaded_handle(parent.handle);

        let result = (|| {
            let (obj_handle, obj_name) = self.load_handle(
                &private,
                &public,
                &parent,
                Some(session_salt_handle),
                Some(&mut resources),
            )?;
            resources.add_transient_handle(obj_handle.inner());
            resources.flush_handle(self, parent.handle.inner())?;

            validate_obj_name(obj_name.as_bytes(), expected_name.as_bytes())?;

            Ok(LoadedHandle::new(obj_handle, obj_name, authorization))
        })();

        self.cleanup_on_error(result, &mut resources)
    }

    pub(crate) fn load_primary_key(
        &mut self,
        primary_handle: TpmiRhHierarchy,
        public: Tpm2bPublic,
        authorization: Authorization,
        primary_authorization: &Authorization,
        session_salt_handle: TpmiDhObject,
        expected_name: &Tpm2bName,
    ) -> Result<LoadedHandle> {
        let mut resources = CommandResources::default();

        let result = (|| {
            let created = self.create_primary(
                primary_handle,
                &public,
                authorization.auth.clone(),
                primary_authorization,
                Some(session_salt_handle),
            )?;
            resources.add_transient_handle(created.handle.into());

            validate_obj_name(created.name.as_bytes(), expected_name.as_bytes())?;

            Ok(LoadedHandle::transient(
                created.handle,
                created.name,
                authorization,
            ))
        })();

        self.cleanup_on_error(result, &mut resources)
    }
}
