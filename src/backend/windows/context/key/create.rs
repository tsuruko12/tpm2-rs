use super::{Command, CommandResources, Context, compute_obj_name};
use super::super::{CreatePrimaryResponse, CreateResponse};
use crate::{
    Error, Result,
    backend::{
        generate_sym_key,
        windows::types::{Tpm2bData, Tpm2bSensitiveCreate, TpmsSensitiveCreate}
    },
    types::{
        Authorization, CreatedKeyData, CreatedObject, KeyTemplate, LoadedHandle,
        LoadedObjectHandle, PolicyData,
        tpm::{TpmaSession, Tpm2bAuth, Tpm2bDigest, Tpm2bPrivate, Tpm2bPublic,
            Tpm2bPublicKeyRsa, TpmCc, TpmMarshal, TpmiDhObject, TpmiRhHierarchy, TpmlPcrSelection},
    },
};

const CREATE_RESPONSE_HANDLE_COUNT: usize = 0;
const CREATE_PRIMARY_RESPONSE_HANDLE_COUNT: usize = 1;

impl Context {
    pub(crate) fn create_child_key_from_template(
        &mut self,
        template: KeyTemplate,
        auth: Tpm2bAuth,
        policy: Option<&mut PolicyData>,
        parent: &LoadedHandle,
        session_salt_handle: TpmiDhObject,
    ) -> Result<CreatedKeyData> {
        let auth_policy = self.get_auth_policy(policy)?;
        let in_public = Tpm2bPublic::from_template(template, auth_policy);
        
        let created = self.create_key(&in_public, auth, parent, session_salt_handle)?;

        Ok(CreatedKeyData {
            public: created.public,
            private: created.private,
            name: created.name,
        })
    }

    pub(crate) fn create_srk_from_template(
        &mut self,
        template: KeyTemplate,
        auth: Tpm2bAuth,
        policy: Option<&mut PolicyData>,
        owner_authorization: &Authorization,
        session_salt_handle: TpmiDhObject,
    ) -> Result<CreatedKeyData> {
        let auth_policy = self.get_auth_policy(policy)?;
        let in_public = Tpm2bPublic::from_template(template, auth_policy);

        let mut created = self.create_primary(
            TpmiRhHierarchy::OWNER,
            &in_public,
            auth,
            owner_authorization,
            Some(session_salt_handle),
        )?;
        self.flush_handle(&mut created.handle)?;

        Ok(CreatedKeyData {
            public: created.public,
            private: created.private,
            name: created.name,
        })
    }

    pub(crate) fn create_sym_key_from_template(
        &mut self,
        template: KeyTemplate,
        mut authorization: Option<&mut Authorization>,
        parent: &LoadedHandle,
        session_salt_handle: TpmiDhObject,
    ) -> Result<(Tpm2bPublicKeyRsa, Option<CreatedKeyData>)> {
        let KeyTemplate::Symmetric(sym_template) = template else {
            return Err(Error::invalid_state("expected symmetric key template"));
        };
        let key_bits = sym_template.key_bits();

        let mut resources = CommandResources::default();

        let result = (|| {
            let (rsa_handle, created_key_data) = match authorization.as_deref_mut() {
                Some(authorization) => {
                    let auth_policy = self.get_auth_policy(authorization.policy.as_mut())?;
                    let in_public = Tpm2bPublic::from_template(template, auth_policy);

                    let created = self.create_and_load_key(
                        &in_public,
                        authorization.auth.clone(),
                        parent,
                        Some(session_salt_handle),
                    )?;
                    resources.add_transient_handle(created.handle);

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
            let rsa_authorization = authorization
                .as_deref()
                .unwrap_or(&parent.authorization);

            let wrapped_sym_key = self.wrap_key(
                rsa_handle,
                rsa_authorization,
                sym_key,
                session_salt_handle,
            )?;
            resources.flush_all_handles(self)?;

            Ok((wrapped_sym_key, created_key_data))
        })();

        self.cleanup_on_error(result, &mut resources)
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
        session_salt_handle: TpmiDhObject,
    ) -> Result<CreatedObject> {
        let mut command_params = marshal_creation_params(in_public, auth)?;

        let mut resources = CommandResources::default();

        let result = (|| {
            let (out_private, out_public) = self.submit_create(
                &mut resources,
                parent,
                &mut command_params,
                TpmaSession::encrypt_decrypt(),
                Some(session_salt_handle),
            )?;
            let name = compute_obj_name(out_public.as_inner())?;

            Ok(CreatedObject {
                handle: TpmiDhObject::RH_NULL,
                public: out_public,
                private: Some(out_private),
                name,
            })
        })();

        self.cleanup_on_error(result, &mut resources)
    }

    pub(crate) fn create_and_load_key(
        &mut self,
        in_public: &Tpm2bPublic,
        auth: Tpm2bAuth,
        parent: &LoadedHandle,
        session_salt_handle: Option<TpmiDhObject>,
    ) -> Result<CreatedObject> {
        // password session is used when session_salt_handle is None
        let mut command_params = marshal_creation_params(in_public, auth)?;
        let session_attrs = match session_salt_handle {
            Some(_) => TpmaSession::encrypt_decrypt().with_continue_session(),
            None => TpmaSession::empty(),
        };

        let mut resources = CommandResources::default();

        let result = (|| {
            let (out_private, out_public) = self.submit_create(
                &mut resources,
                parent,
                &mut command_params,
                session_attrs,
                session_salt_handle,
            )?;

            let (handle, name) = self
                .load_handle(
                    &out_private,
                    &out_public,
                    parent,
                    session_salt_handle,
                    Some(&mut resources),
                )
                .map(|(handle, name)| (handle.inner(), name))?;

            Ok(CreatedObject {
                handle,
                public: out_public,
                private: Some(out_private),
                name,
            })
        })();

        self.cleanup_on_error(result, &mut resources)
    }

    fn submit_create(
        &mut self,
        resources: &mut CommandResources,
        parent: &LoadedHandle,
        command_params: &mut [u8],
        session_attrs: TpmaSession,
        session_salt_handle: Option<TpmiDhObject>,
    ) -> Result<(Tpm2bPrivate, Tpm2bPublic)> {
        let authorization_area = self.prepare_sessions(
            resources,
            session_attrs,
            Some(&parent.authorization),
            session_salt_handle,
        )?;
        let mut command = Command::new(TpmCc::CREATE)
            .with_handles([parent.handle.inner()])
            .with_authorization_area(authorization_area)
            .with_parameters(command_params);

        let response_body = self.submit(&mut command, CREATE_RESPONSE_HANDLE_COUNT, resources)?;

        CreateResponse::try_from(response_body)
            .map(|response| (response.out_private, response.out_public))
    }

    pub(crate) fn create_primary(
        &mut self,
        primary_handle: TpmiRhHierarchy,
        in_public: &Tpm2bPublic,
        auth: Tpm2bAuth,
        primary_authorization: &Authorization,
        session_salt_handle: Option<TpmiDhObject>,
    ) -> Result<CreatedObject> {
        // password session is used when session_salt_handle is None
        let mut command_params = marshal_creation_params(in_public, auth)?;
        let session_attrs = match session_salt_handle {
            Some(_) => TpmaSession::encrypt_decrypt(),
            None => TpmaSession::empty(),
        };

        let mut resources = CommandResources::default();

        let result = (|| {
            let authorization_area = self.prepare_sessions(
                &mut resources,
                session_attrs,
                Some(primary_authorization),
                session_salt_handle,
            )?;

            let mut command = Command::new(TpmCc::CREATE_PRIMARY)
                .with_handles([primary_handle])
                .with_authorization_area(authorization_area)
                .with_parameters(&mut command_params);

            let response_body = self.submit(
                &mut command,
                CREATE_PRIMARY_RESPONSE_HANDLE_COUNT,
                &mut resources,
            )?;
            let CreatePrimaryResponse {
                object_handle,
                out_public,
                name,
                ..
            } = CreatePrimaryResponse::try_from(response_body)?;
            let handle =
                TpmiDhObject::try_from(object_handle).expect("loaded handle must be transient");

            Ok(CreatedObject {
                handle,
                public: out_public,
                private: None,
                name,
            })
        })();

        self.cleanup_on_error(result, &mut resources)
    }
}

fn marshal_creation_params(in_public: &Tpm2bPublic, auth: Tpm2bAuth) -> Result<Vec<u8>> {
    let in_sensitive = Tpm2bSensitiveCreate::from(TpmsSensitiveCreate::asymmetric(auth));
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let mut command_params = Vec::new();
    in_sensitive.marshal(&mut command_params)?;
    in_public.marshal(&mut command_params)?;
    outside_info.marshal(&mut command_params)?;
    creation_pcr.marshal(&mut command_params)?;

    Ok(command_params)
}
