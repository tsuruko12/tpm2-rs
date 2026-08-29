use tss_esapi::{
    handles::{KeyHandle, ObjectHandle},
    interface_types::resource_handles::Hierarchy as EsapiHierarchy,
    structures::{Private, Public},
};

use super::{CommandResources, Context, compute_obj_name};
use crate::{
    Error, Result,
    backend::generate_sym_key,
    types::{
        Authorization, CreatedKeyData, CreatedObject, KeyTemplate, LoadedHandle,
        LoadedObjectHandle, PolicyData,
        tpm::{
            Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, Tpm2bPublicKeyRsa, TpmaSession, TpmiRhHierarchy,
        },
    },
};

impl Context {
    pub(crate) fn create_child_key_from_template(
        &mut self,
        template: KeyTemplate,
        auth: Tpm2bAuth,
        policy: Option<&mut PolicyData>,
        parent: &LoadedHandle,
        session_salt_handle: ObjectHandle,
    ) -> Result<CreatedKeyData> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle);

        let result = (|| {
            let auth_policy = self.get_auth_policy(policy)?;
            let in_public = Tpm2bPublic::from_template(template, auth_policy);

            let created = self.create_key(&in_public, auth, parent, session_salt_handle)?;
            resources.close_all_handles(self)?;

            Ok(CreatedKeyData {
                public: created.public,
                private: created.private,
                name: created.name,
            })
        })();

        self.finalize_command(result, &mut resources)
    }

    pub(crate) fn create_srk_from_template(
        &mut self,
        template: KeyTemplate,
        auth: Tpm2bAuth,
        policy: Option<&mut PolicyData>,
        owner_authorization: &Authorization,
        session_salt_handle: ObjectHandle,
    ) -> Result<CreatedKeyData> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle);

        let result = (|| {
            let auth_policy = self.get_auth_policy(policy)?;
            let in_public = Tpm2bPublic::from_template(template, auth_policy);

            let created = self.create_primary(
                TpmiRhHierarchy::OWNER,
                in_public,
                auth,
                owner_authorization,
                Some(session_salt_handle.into()),
            )?;
            resources.add_transient_handle(created.handle.into());

            resources.release_all_handles(self)?;

            Ok(CreatedKeyData {
                public: created.public,
                private: created.private,
                name: created.name,
            })
        })();

        self.finalize_command(result, &mut resources)
    }

    pub(crate) fn create_sym_key_from_template(
        &mut self,
        template: KeyTemplate,
        mut authorization: Option<&mut Authorization>,
        parent: &LoadedHandle,
        session_salt_handle: ObjectHandle,
    ) -> Result<(Tpm2bPublicKeyRsa, Option<CreatedKeyData>)> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle);

        let result = (|| {
            let KeyTemplate::Symmetric(sym_template) = template else {
                return Err(Error::invalid_state("expected symmetric key template"));
            };

            let key_bits = sym_template.key_bits();
            let (rsa_handle, created_key_data) = match authorization.as_deref_mut() {
                Some(authorization) => {
                    let auth_policy = self.get_auth_policy(authorization.policy.as_mut())?;
                    let in_public = Tpm2bPublic::from_template(template, auth_policy);

                    let created = self.create_and_load_key(
                        in_public,
                        authorization.auth.clone(),
                        parent,
                        Some(session_salt_handle.into()),
                    )?;
                    resources.add_transient_handle(created.handle.into());

                    (
                        LoadedObjectHandle::Transient(created.handle),
                        Some(CreatedKeyData {
                            public: created.public,
                            private: created.private,
                            name: created.name,
                        }),
                    )
                }
                None => (parent.handle, None),
            };

            let sym_key = generate_sym_key(key_bits)?;
            let wrapped_sym_key = self.wrap_key(
                rsa_handle,
                authorization.as_deref().unwrap_or(&parent.authorization),
                sym_key,
                session_salt_handle.into(),
            )?;

            resources.release_all_handles(self)?;

            Ok((wrapped_sym_key, created_key_data))
        })();

        self.finalize_command(result, &mut resources)
    }

    fn get_auth_policy(&mut self, policy: Option<&mut PolicyData>) -> Result<Tpm2bDigest> {
        match policy {
            Some(policy) => self.compute_auth_policy(policy),
            None => Ok(Tpm2bDigest::default()),
        }
    }

    pub(crate) fn create_key(
        &mut self,
        in_public: &Tpm2bPublic,
        auth: Tpm2bAuth,
        parent: &LoadedHandle,
        session_salt_handle: ObjectHandle,
    ) -> Result<CreatedObject> {
        let mut resources = CommandResources::default();

        let result = (|| {
            let (out_private, out_public) = self.execute_create(
                &mut resources,
                parent,
                in_public,
                auth,
                Some(session_salt_handle.into()),
            )?;
            let name = compute_obj_name(&out_public)?;

            Ok(CreatedObject {
                handle: ObjectHandle::Null,
                public: out_public.try_into()?,
                private: Some(out_private.into()),
                name,
            })
        })();

        self.finalize_command(result, &mut resources)
    }

    pub(crate) fn create_and_load_key(
        &mut self,
        in_public: Tpm2bPublic,
        auth: Tpm2bAuth,
        parent: &LoadedHandle,
        session_salt_handle: Option<ObjectHandle>,
    ) -> Result<CreatedObject> {
        // use password session when session_salt_handle is None
        let mut resources = CommandResources::default();
        if let Some(handle) = session_salt_handle {
            resources.add_persistent_handle(handle);
        }

        let result = (|| {
            let (out_private, out_public) = self.execute_create(
                &mut resources,
                parent,
                &in_public,
                auth,
                session_salt_handle.map(Into::into),
            )?;

            let (handle, name) = self.load_handle(
                out_private.clone(),
                out_public.clone(),
                parent,
                session_salt_handle,
                Some(&mut resources),
            )
            .map(|(handle, name)| (handle.inner(), name))?;

            Ok(CreatedObject {
                handle,
                public: out_public.try_into()?,
                private: Some(out_private.into()),
                name,
            })
        })();

        self.finalize_command(result, &mut resources)
    }

    fn execute_create(
        &mut self,
        resources: &mut CommandResources,
        parent: &LoadedHandle,
        in_public: &Tpm2bPublic,
        auth: Tpm2bAuth,
        session_salt_handle: Option<KeyHandle>,
    ) -> Result<(Private, Public)> {
        let in_public = Public::try_from(in_public)?;
        let parent_handle = parent.handle.inner();

        let session_attrs = match session_salt_handle {
            Some(_) => TpmaSession::encrypt_decrypt().with_continue_session(),
            None => TpmaSession::empty(),
        };
        self.prepare_sessions(
            resources,
            session_attrs,
            Some((parent_handle, &parent.authorization)),
            session_salt_handle,
        )?;

        self.ctx
            .execute_with_sessions(resources.session_slots(), |ctx| {
                ctx.create(
                    parent_handle.into(),
                    in_public,
                    Some(auth.into()),
                    None,
                    None,
                    None,
                )
            })
            .map(|created| (created.out_private, created.out_public))
            .map_err(Error::from_tss_err)
    }

    pub(crate) fn create_primary(
        &mut self,
        primary_handle: TpmiRhHierarchy,
        in_public: Tpm2bPublic,
        auth: Tpm2bAuth,
        primary_authorization: &Authorization,
        session_salt_handle: Option<ObjectHandle>,
    ) -> Result<CreatedObject> {
        let in_public = Public::try_from(in_public)?;
        let primary_handle = EsapiHierarchy::try_from(primary_handle)
            .map_err(|_| Error::invalid_state("unexpected primary hierarchy"))?;
        let session_attrs = match session_salt_handle {
            Some(_) => TpmaSession::encrypt_decrypt(),
            None => TpmaSession::continue_session(),
        };

        let mut resources = CommandResources::default();

        let result = (|| {
            self.prepare_sessions(
                &mut resources,
                session_attrs,
                Some((primary_handle.into(), primary_authorization)),
                session_salt_handle.map(Into::into),
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
                .map(|created| (ObjectHandle::from(created.key_handle), created.out_public))
                .map_err(Error::from_tss_err)?;
            resources.add_transient_handle(handle);

            let name = compute_obj_name(&out_public)?;

            Ok(CreatedObject {
                handle,
                public: out_public.try_into()?,
                private: None,
                name,
            })
        })();

        self.finalize_command(result, &mut resources)
    }
}
