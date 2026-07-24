use crate::{Result, types::{LoadedParent, TpmCc, TpmHandle, TpmiDhObject, TpmtPublic}};
use super::{
    Context, 
    codec::{LoadResponse, TpmMarshal, marshal_tpm2b, tpm2b_payload_mut},
    commands::Command,
    session::{
        CpHashData, HmacSessionState, encrypt_command_parameter, decrypt_response_parameter,
        split_prepared_sessions, update_command_hmacs
    },
    types::{TpmaSession, Tpm2bName, Tpm2bPrivate}
};

impl Context {
    pub(super) fn load_handle(
        &mut self,
        private: &Tpm2bPrivate,
        public: &TpmtPublic,
        parent: &LoadedParent,
        session_salt_key_handle: Option<TpmiDhObject>,
        hmac_session_state: Option<HmacSessionState>,
    ) -> Result<(TpmHandle, Tpm2bName)> {
        let mut request_params = Vec::new();
        marshal_tpm2b(&mut request_params, private.as_bytes())?;
        public.marshal(&mut request_params)?;

        let command_code = TpmCc::LOAD;
        let parent_name = self.read_object_name(parent.handle())?;

        let mut sessions = self.prepare_sessions(
            parent.authorization(), 
            TpmaSession::encrypt_decrypt(),
            session_salt_key_handle.into(), 
            hmac_session_state,
        )?;

        if session_salt_key_handle.is_some() {
            let param = tpm2b_payload_mut(&mut request_params)?;
            encrypt_command_parameter(&sessions, param)?;

            let cp_hash_data = CpHashData {
                command_code,
                handle_names: &[&parent_name],
                parameters: &request_params,
            };
            update_command_hmacs(&mut sessions, &cp_hash_data)?;            
        }

        let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);

        let command = Command::new(TpmCc::LOAD)
            .with_handles(vec![parent.handle().into()])
            .with_parameters(&request_params)
            .with_authorizations(&authorizations);
        
        let response_body = self.submit(command)?;
        self.clear_sessions();
        
        let mut response = LoadResponse::parse(&response_body, auth_contexts.len())?;

        if session_salt_key_handle.is_some() {
            decrypt_response_parameter(
                command_code,
                &mut response.parameters,
                &auth_contexts,
                &response.authorizations,
            )?;            
        }

        response.into_parts()
    }
}
