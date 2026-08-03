use super::{
    Context, CommandResources,
    codec::{CreatePrimaryResponse, CreateResponse, TpmMarshal, marshal_tpm2b, tpm2b_payload_mut},
    commands::{Command, TpmsAuthCommand},
    session::{
        CpHashData, HmacSessionState, decrypt_response_parameter, encrypt_command_parameter,
        find_hmac_session, split_prepared_sessions, update_command_hmacs,
    },
    types::{Tpm2bData, TpmaSession, TpmiRhHierarchy, TpmsSensitiveCreate},
};
use crate::{
    Error, Result,
    types::{
        Authorization, CreatedObject, LoadedParent, Tpm2bAuth, TpmCc, TpmiDhObject,
        TpmlPcrSelection, TpmtPublic,
    },
};

impl Context {
    pub(crate) fn create_and_load(
        &mut self,
        public: &TpmtPublic,
        auth: Tpm2bAuth,
        parent: &LoadedParent,
        session_salt_key_handle: Option<TpmiDhObject>,
    ) -> Result<CreatedObject> {
        // use password session when session_salt_key is None
        let mut request_params = Vec::new();

        marshal_tpm2b(&mut request_params, &TpmsSensitiveCreate::asymmetric(auth))?;
        marshal_tpm2b(&mut request_params, public)?;
        marshal_tpm2b(&mut request_params, Tpm2bData::default().as_bytes())?;
        TpmlPcrSelection::default().marshal(&mut request_params)?;

        let mut resources = CommandResources::default();

        let command_code = TpmCc::CREATE;

        let result = (|| {
            let (out_private, out_public, hmac_session_state) = match session_salt_key_handle {
                Some(_) => {
                    let mut sessions = self.prepare_sessions(
                        &mut resources,
                        parent.authorization(),
                        TpmaSession::encrypt_decrypt().with_continue_session(),
                        session_salt_key_handle,
                        None,
                    )?;   
                    
                    let param = tpm2b_payload_mut(&mut request_params)?;
                    encrypt_command_parameter(&sessions, param)?;

                    let cp_hash_data = CpHashData {
                        command_code,
                        handle_names: &[parent.name()],
                        parameters: &request_params,
                    };
                    update_command_hmacs(&mut sessions, &cp_hash_data)?;

                    let (authorizations, _) = split_prepared_sessions(&sessions);
                    let hmac_session = find_hmac_session(&sessions);        

                    let command = Command::new(command_code)
                        .with_handles([parent.handle().into()])
                        .with_authorizations(&authorizations)
                        .with_parameters(&request_params);

                    let response_body = self.submit(command)?;
                    resources.clear_policy_session();

                    let (_, auth_contexts) = split_prepared_sessions(&sessions);
                    let mut response = CreateResponse::parse(&response_body, auth_contexts.len())?;
            
                    decrypt_response_parameter(
                        command_code,
                        &mut response.parameters,
                        &auth_contexts,
                        &response.authorizations,
                    )?;

                    let (out_private, out_public, auth_responses) = response.into_parts()?;

                    let hmac_idx = hmac_session
                        .ok_or_else(|| Error::invalid_state("expected HMAC session was not found"))?;
                    let hmac_session_state =
                        HmacSessionState::from_response(hmac_idx, sessions, auth_responses)?;

                    (out_private, out_public, Some(hmac_session_state))      
                },
                None => {
                    let authorizations = [&TpmsAuthCommand::password()];
                    let command = Command::new(command_code)
                        .with_handles([parent.handle().into()])
                        .with_authorizations(&authorizations)
                        .with_parameters(&request_params);

                    let response_body = self.submit(command)?;
                    let (out_private, out_public, _) = CreateResponse::parse(
                        &response_body, 
                        authorizations.len(),
                    )?
                    .into_parts()?;

                    (out_private, out_public, None)
                }
            };

            let (handle, name) = self.load_handle(
                &out_private,
                &out_public,
                parent,
                session_salt_key_handle,
                hmac_session_state,
                Some(&mut resources),
            )?;

            Ok(CreatedObject {
                handle: handle.try_into()?,
                public: out_public.into(),
                private: Some(out_private),
                name,
            })               
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn create_owner_primary(
        &mut self,
        public: &TpmtPublic,
        owner_authorization: &Authorization,
        session_salt_key_handle: Option<TpmiDhObject>,
    ) -> Result<CreatedObject> {
        let mut request_params = Vec::new();

        marshal_tpm2b(
            &mut request_params,
            &TpmsSensitiveCreate::asymmetric(Tpm2bAuth::default()),
        )?;
        marshal_tpm2b(&mut request_params, public)?;
        marshal_tpm2b(&mut request_params, Tpm2bData::default().as_bytes())?;
        TpmlPcrSelection::default().marshal(&mut request_params)?;

        let mut resources = CommandResources::default();

        let command_code = TpmCc::CREATE_PRIMARY;
        let owner_handle = TpmiRhHierarchy::OWNER;
        let session_attrs = match session_salt_key_handle {
            Some(_) => TpmaSession::encrypt_decrypt(),
            None => TpmaSession::empty(),
        };

        let result = (|| {
            let mut sessions = self.prepare_sessions(
                &mut resources,
                owner_authorization,
                session_attrs,
                session_salt_key_handle,
                None,
            )?;

            if session_salt_key_handle.is_some() {
                let param = tpm2b_payload_mut(&mut request_params)?;
                encrypt_command_parameter(&sessions, param)?;
            }

            let cp_hash_data = CpHashData {
                command_code,
                handle_names: &[&owner_handle.raw().to_be_bytes()],
                parameters: &request_params,
            };
            update_command_hmacs(&mut sessions, &cp_hash_data)?;

            let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);

            let command = Command::new(command_code)
                .with_handles([owner_handle.into()])
                .with_authorizations(&authorizations)
                .with_parameters(&request_params);

            let response_body = self.submit(command)?;
            resources.clear_sessions();

            let mut response = CreatePrimaryResponse::parse(&response_body, auth_contexts.len())?;
            resources.add_transient_handle(response.object_handle.try_into()?);

            match session_salt_key_handle {
                Some(_) => {
                    decrypt_response_parameter(
                        command_code,
                        &mut response.parameters,
                        &auth_contexts,
                        &response.authorizations,
                    )?;                
                },
                None => {
                    auth_contexts
                        .iter()
                        .zip(response.authorizations.iter())
                        .filter(|(auth_context, _)| auth_context.requires_hmac())
                        .try_for_each(|(auth_context, auth_response)| {
                            auth_context.verify_hmac(command_code, &response.parameters, auth_response)
                        })?;                
                },
            }

            let (handle, out_public, name) = response.into_parts()?;

            Ok(CreatedObject {
                handle: handle.try_into()?,
                public: out_public.into(),
                private: None,
                name,
            })
        })();

        self.finish_command(result, &mut resources)
    }
}
