use tss_esapi::{
    handles::KeyHandle,
    interface_types::{resource_handles::Hierarchy as EsapiHierarchy, session_handles::AuthSession},
    structures::Public,
};

use crate::{
    Error, Result, generate_sym_key, 
    types::{
        Authorization, CreatedKeyData, CreatedObject, KeyTemplate, LoadedHandle, LoadedObjectHandle, 
        PolicyData, Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, Tpm2bPublicKeyRsa, 
        TpmaSession, TpmiRhHierarchy
    }
};

use super::Context;
use super::super::CommandResources;

impl Context {
    pub(crate) fn create_child_key_from_template(
        &mut self,
        template: &KeyTemplate,
        auth: Tpm2bAuth,
        policy: Option<&PolicyData>,
        parent: &LoadedHandle,
        session_salt_handle: KeyHandle,
    ) -> Result<CreatedKeyData> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle.into());

        let result = (|| {
            let auth_policy = self.get_auth_policy(policy)?;
            let in_public = Tpm2bPublic::from_template(template, auth_policy);

            let created = self.create_and_load(
                in_public, 
                auth, 
                parent, 
                Some(session_salt_handle)
            )?;
            resources.add_transient_handle(created.handle.into());

            resources.release_all_handles(self)?;

            Ok(CreatedKeyData {
                public: created.public,
                private: created.private,
                name: created.name
            })
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn create_srk_from_template(
        &mut self,
        template: &KeyTemplate,
        auth: Tpm2bAuth,
        policy: Option<&PolicyData>,
        owner_authorization: &Authorization,
        session_salt_handle: KeyHandle,
    ) -> Result<CreatedKeyData> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle.into());

        let result = (|| {
            let auth_policy = self.get_auth_policy(policy)?;
            let in_public = Tpm2bPublic::from_template(template, auth_policy);

            let created = self.create_primary(
                TpmiRhHierarchy::OWNER, 
                in_public, 
                auth, 
                owner_authorization, 
                Some(session_salt_handle)
            )?;
            resources.add_transient_handle(created.handle.into());

            resources.release_all_handles(self)?;

            Ok(CreatedKeyData {
                public: created.public,
                private: created.private,
                name: created.name
            })            
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn create_sym_key_from_template(
        &mut self, 
        template: &KeyTemplate,
        authorization: Option<&Authorization>,
        parent: &LoadedHandle,
        session_salt_handle: KeyHandle,
    ) -> Result<(Tpm2bPublicKeyRsa, Option<CreatedKeyData>)> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle.into());

        let result = (|| {
            let KeyTemplate::Symmetric(sym_template) = template else {
                return Err(Error::invalid_state("expected symmetric key template"));
            };

            let key_bits = sym_template.key_bits();
            let (rsa_handle, created) = match authorization {
                Some(authorization) => {
                    let auth_policy = self.get_auth_policy(authorization.policy())?;
                    let in_public = Tpm2bPublic::from_template(template, auth_policy);

                    let created = self.create_and_load(
                        in_public, 
                        authorization.auth().clone(), 
                        parent, 
                        Some(session_salt_handle)
                    )?;
                    resources.add_transient_handle(created.handle.into());

                    (
                        LoadedObjectHandle::Transient(created.handle), 
                        Some(CreatedKeyData { 
                            public: created.public, 
                            private: created.private, 
                            name: created.name 
                        })
                    )
                },
                None => (parent.handle(), None),
            };

            let sym_key = generate_sym_key(key_bits)?;
            let wrapped_sym_key = self.wrap_key(
                rsa_handle, 
                authorization.unwrap_or_else(|| parent.authorization()),
                sym_key, 
                session_salt_handle
            )?;

            resources.release_all_handles(self)?;

            Ok((wrapped_sym_key, created))
        })();

        self.finish_command(result, &mut resources)
    }

    fn get_auth_policy(&mut self, policy: Option<&PolicyData>) -> Result<Tpm2bDigest> {
        match policy {
            Some(policy) => self.compute_auth_policy(policy),
            None => Ok(Tpm2bDigest::default()),
        }
    }

    pub(crate) fn create_and_load(
        &mut self,
        in_public: Tpm2bPublic,
        auth: Tpm2bAuth,
        parent: &LoadedHandle,
        session_salt_handle: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        // use password session when session_salt_handle is None
        let mut resources = CommandResources::default();

        let parent_handle = parent.handle();
        let in_public = Public::try_from(in_public)?;

        let result = (|| {
            match session_salt_handle {
                Some(_) => {
                    self.prepare_sessions(
                        &mut resources,
                        Some((parent_handle.inner().into(), parent.authorization())),
                        TpmaSession::encrypt_decrypt().with_continue_session(),
                        session_salt_handle,
                    )?; 
                },
                None => resources.add_session(AuthSession::Password)?,
            }

            let (out_private, out_public) = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.create(
                        parent_handle.inner(),
                        in_public,
                        Some(auth.into()),
                        None,
                        None,
                        None,
                    )
                })
                .map(|created| (created.out_private, created.out_public))
                .map_err(Error::from_tss_err)?;

            match session_salt_handle {
                Some(_) => resources.flush_policy_session(self)?,
                None => resources.clear_password_session(),
            }

            let (handle, name) = self.load_handle(
                out_private.clone(),
                out_public.clone(),
                parent,
                session_salt_handle,
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
        session_salt_handle: Option<KeyHandle>,
    ) -> Result<CreatedObject> {
        let mut resources = CommandResources::default();
        
        let in_public = Public::try_from(in_public)?;
        let primary_handle = EsapiHierarchy::try_from(primary_handle)
            .map_err(|_| Error::invalid_state("unexpected primary hierarchy"))?;
        let session_attrs = match session_salt_handle {
            Some(_) => TpmaSession::encrypt_decrypt().with_continue_session(),
            None => TpmaSession::continue_session(),
        };

        let result = (|| {
            self.prepare_sessions(
                &mut resources,
                Some((primary_handle.into(), primary_authorization)),
                session_attrs,
                session_salt_handle,
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
