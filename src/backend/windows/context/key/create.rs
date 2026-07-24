use crate::{
    Error, Result, 
    types::{
        Authorization, LoadedParent, TpmCc, TpmHandle, TpmiDhObject, TpmlPcrSelection, TpmtPublic,
        Tpm2bAuth
    }
};
use super::{
    codec::{CreateResponse, CreatePrimaryResponse, TpmMarshal, 
        marshal_tpm2b, tpm2b_payload_mut},
    commands::Command,
    Context, 
    session::{
        CpHashData, HmacSessionState, decrypt_response_parameter, encrypt_command_parameter,
        find_hmac_session, split_prepared_sessions, update_command_hmacs,
    },
    types::{
        TpmaSession, TpmiRhHierarchy, TpmsSensitiveCreate, Tpm2bData, 
        Tpm2bName, Tpm2bPrivate
    }
};

#[derive(Debug)]
pub(crate) struct CreatedObject {
    pub(crate) handle: TpmHandle,
    pub(crate) public: TpmtPublic,
    pub(crate) private: Option<Tpm2bPrivate>,
    pub(crate) name: Tpm2bName,
}

impl Context {
    pub(crate) fn create_and_load(
        &mut self, 
        public: &TpmtPublic,
        auth: Tpm2bAuth,
        parent: &LoadedParent,
        session_salt_key_handle: Option<TpmiDhObject>,
    ) -> Result<CreatedObject> {
        let mut request_params = Vec::new();

        marshal_tpm2b(&mut request_params, &TpmsSensitiveCreate::asymmetric(auth))?;
        marshal_tpm2b(&mut request_params, public)?;
        marshal_tpm2b(&mut request_params, Tpm2bData::default().as_bytes())?;
        TpmlPcrSelection::default().marshal(&mut request_params)?;

        let command_code = TpmCc::CREATE;

        let mut sessions = self.prepare_sessions(
            parent.authorization(), 
            TpmaSession::encrypt_decrypt().with_continue_session(),
            session_salt_key_handle, 
            None,
        )?;

        if session_salt_key_handle.is_some() {
            let param = tpm2b_payload_mut(&mut request_params)?;
            encrypt_command_parameter(&sessions, param)?;

            let cp_hash_data = CpHashData {
                command_code,
                handle_names: &[parent.name()],
                parameters: &request_params,
            };
            update_command_hmacs(&mut sessions, &cp_hash_data)?;            
        }

        let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);
        let hmac_session = find_hmac_session(&sessions);

        let command = Command::new(command_code)
            .with_handles([parent.handle().into()])
            .with_authorizations(&authorizations)
            .with_parameters(&request_params);

        let response_body = self.submit(command)?;
        self.clear_policy_session();

        let mut response = CreateResponse::parse(&response_body, auth_contexts.len())?;

        let (out_private, out_public, hmac_session_state) = if session_salt_key_handle.is_some() {
            decrypt_response_parameter(
                command_code,
                &mut response.parameters,
                &auth_contexts,
                &response.authorizations,
            )?;

            let (out_private, out_public, auth_responses) = response.into_parts()?;

            let hmac_idx = hmac_session
                .ok_or_else(|| Error::invalid_state("expected HMAC session was not found"))?;
            let hmac_session_state = HmacSessionState::from_response(
                hmac_idx, 
                sessions,
                auth_responses,
            )?;

            (out_private, out_public, Some(hmac_session_state))
        } else {
            let (out_private, out_public, _) = response.into_parts()?;
            (out_private, out_public, None)
        };

        let (handle, name) = self.load_handle(
            &out_private, 
            &out_public, 
            parent, 
            session_salt_key_handle, 
            hmac_session_state,
        )?;

        Ok(CreatedObject { handle, public: out_public.into(), private: Some(out_private), name })
    }

    pub(crate) fn create_owner_primary(
        &mut self, 
        public: &TpmtPublic, 
        owner_authorization: &Authorization,
        session_salt_key_handle: Option<TpmiDhObject>,
    ) -> Result<CreatedObject> {        
        let mut request_params = Vec::new();

        marshal_tpm2b(&mut request_params, &TpmsSensitiveCreate::asymmetric(
            Tpm2bAuth::default())
        )?;
        marshal_tpm2b(&mut request_params, public)?;
        marshal_tpm2b(&mut request_params, Tpm2bData::default().as_bytes())?;
        TpmlPcrSelection::default().marshal(&mut request_params)?;

        let command_code = TpmCc::CREATE_PRIMARY;
        let owner_handle = TpmiRhHierarchy::OWNER;

        let mut sessions = self.prepare_sessions(
            owner_authorization, 
            TpmaSession::encrypt_decrypt(),
            session_salt_key_handle,
            None,
        )?;

        if session_salt_key_handle.is_some() {
            let param = tpm2b_payload_mut(&mut request_params)?;
            encrypt_command_parameter(&sessions, param)?;

            let cp_hash_data = CpHashData {
                command_code,
                handle_names: &[&owner_handle.raw().to_be_bytes()],
                parameters: &request_params,
            };
            update_command_hmacs(&mut sessions, &cp_hash_data)?;            
        }

        let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);

        let command = Command::new(command_code)
            .with_handles([owner_handle.into()])
            .with_authorizations(&authorizations)
            .with_parameters(&request_params);

        let response_body = self.submit(command)?;
        self.clear_sessions();

        let mut response = CreatePrimaryResponse::parse(&response_body, auth_contexts.len())?;

        if session_salt_key_handle.is_some() {
            decrypt_response_parameter(
                command_code,
                &mut response.parameters,
                &auth_contexts,
                &response.authorizations,
            )?;            
        }

        let (handle, out_public, name) = response.into_parts()?;

        Ok(CreatedObject { handle, public: out_public.into(), private: None, name })
    }
}
