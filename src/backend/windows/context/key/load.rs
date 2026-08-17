use super::{
    Context, CommandResources,
    codec::{LoadResponse, marshal_tpm2b, tpm2b_payload_mut},
    commands::{Command, TpmsAuthCommand},
    session::{
        HmacSessionState, decrypt_response_parameter, encrypt_command_parameter,
        split_prepared_sessions, update_command_hmacs,
    },
    types::{Tpm2bName, Tpm2bPrivate, TpmaSession},
};
use crate::{
    Result, 
    types::{LoadedHandle, LoadedObjectHandle, Tpm2bPublic, Tpm2bName, TpmCc, TpmHandle, TpmiDhObject},
};

impl Context {
    pub(super) fn load_handle(
        &mut self,
        in_private: &Tpm2bPrivate,
        in_public: &Tpm2bPublic,
        parent: &LoadedHandle,
        session_salt_handle: Option<TpmiDhObject>,
        hmac_session_state: Option<HmacSessionState>,
        caller_resources: Option<&mut CommandResources>,
    ) -> Result<(LoadedObjectHandle, Tpm2bName)> {
        let mut request_params = Vec::new();
        marshal_tpm2b(&mut request_params, in_private.as_bytes())?;
        marshal_tpm2b(&mut request_params, in_public.as_inner())?;

        let mut default_resources = CommandResources::default();
        let resources = caller_resources.unwrap_or(&mut default_resources);

        let parent_handle = parent.handle();
        let command_code = TpmCc::LOAD;

        let result = (|| {
            match session_salt_handle {
                Some(_) => {
                    let mut sessions = self.prepare_sessions(
                        resources,
                        TpmaSession::encrypt_decrypt().with_continue_session(),
                        Some(parent.authorization()),
                        session_salt_handle,
                        hmac_session_state,
                    )?;

                    let parent_name = self.read_object_name(parent_handle)?;

                    let first_param = tpm2b_payload_mut(&mut request_params)?;
                    encrypt_command_parameter(&sessions, first_param)?;

                    update_command_hmacs(
                        &mut sessions,
                        command_code,
                        &[&parent_name],
                        &request_params,
                    )?;

                    let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);

                    let command = Command::new(command_code)
                        .with_handles(vec![parent_handle.into()])
                        .with_parameters(&request_params)
                        .with_authorizations(&authorizations);

                    let response_body = self.submit(command)?;
                    resources.clear_policy_session();
                    
                    let mut response = LoadResponse::parse(&response_body, auth_contexts.len())?;
                    resources.add_transient_handle(response.object_handle.try_into()?);

                    decrypt_response_parameter(
                        command_code,
                        &mut response.parameters,
                        &auth_contexts,
                        &response.authorizations,
                    )?;

                    response.into_parts()
                },
                None => {
                    let authorizations = [&TpmsAuthCommand::password()];
                    let command = Command::new(command_code)
                        .with_handles(vec![parent.handle().into()])
                        .with_parameters(&request_params)
                        .with_authorizations(&authorizations);

                    let response_body = self.submit(command)?;
                    LoadResponse::parse(&response_body, authorizations.len())?.into_parts()
                },
            }            
        })();

        self.finish_command(result, resources)
    }

    pub(crate) fn resolve_persistent_handle(
        &mut self, 
        persistent_handle: TpmiDhPersistent,
        obj_name: &Tpm2bName,
    ) -> Result<ObjectHandle> {
        let obj_handle = TpmiDhObject::from(persistent_handle);
        self.validate_obj_name(obj_handle, obj_name, None)?;

        Ok(obj_handle)
    }

    pub(crate) fn resolve_internal_key(
        &mut self, 
        key_meta: InternalKeyMeta,
    ) -> Result<LoadedHandle> {
        self.validate_obj_name(key_meta.handle, &key_meta.name, None)?;

        Ok(LoadedHandle::internal_persistent(
            key_meta.handle.into(), 
            key_meta.object_name,
        ))
    }
}
