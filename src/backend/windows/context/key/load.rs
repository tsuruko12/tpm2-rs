use super::{
    Context, CommandResources,
    codec::{LoadResponse, TpmMarshal, marshal_tpm2b, tpm2b_payload_mut},
    commands::{Command, TpmsAuthCommand},
    session::{
        CpHashData, HmacSessionState, decrypt_response_parameter, encrypt_command_parameter,
        split_prepared_sessions, update_command_hmacs,
    },
    types::{Tpm2bName, Tpm2bPrivate, TpmaSession},
};
use crate::{
    Result,
    types::{LoadedParent, TpmCc, TpmHandle, TpmiDhObject, TpmtPublic},
};

impl Context {
    pub(super) fn load_handle(
        &mut self,
        private: &Tpm2bPrivate,
        public: &TpmtPublic,
        parent: &LoadedParent,
        session_salt_key_handle: Option<TpmiDhObject>,
        hmac_session_state: Option<HmacSessionState>,
        caller_resources: Option<&mut CommandResources>,
    ) -> Result<(TpmHandle, Tpm2bName)> {
        let mut request_params = Vec::new();
        marshal_tpm2b(&mut request_params, private.as_bytes())?;
        public.marshal(&mut request_params)?;

        let mut default_resources = CommandResources::default();
        let resources = caller_resources.unwrap_or(&mut default_resources);

        let parent_handle = parent.handle();
        let command_code = TpmCc::LOAD;

        let result = (|| {
            match session_salt_key_handle {
                Some(_) => {
                    let mut sessions = self.prepare_sessions(
                        resources,
                        parent.authorization(),
                        TpmaSession::encrypt_decrypt().with_continue_session(),
                        session_salt_key_handle,
                        hmac_session_state,
                    )?;

                    let parent_name = self.read_object_name(parent_handle)?;

                    let param = tpm2b_payload_mut(&mut request_params)?;
                    encrypt_command_parameter(&sessions, param)?;

                    let cp_hash_data = CpHashData {
                        command_code,
                        handle_names: &[&parent_name],
                        parameters: &request_params,
                    };
                    update_command_hmacs(&mut sessions, &cp_hash_data)?;

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
}
