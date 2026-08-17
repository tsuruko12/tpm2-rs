use super::{
    Context, CommandResources,
    codec::{CreatePrimaryResponse, CreateResponse, TpmMarshal, marshal_tpm2b, tpm2b_payload_mut},
    commands::{Command, TpmsAuthCommand},
    session::{
        HmacSessionState, decrypt_response_parameter, encrypt_command_parameter,
        find_hmac_session, split_prepared_sessions, update_command_hmacs,
    },
    types::{Tpm2bData, TpmaSession, TpmiRhHierarchy, TpmsSensitiveCreate},
};
use crate::{
    Error, Result,
    types::{
        Authorization, CreatedObject, LoadedHandle, Tpm2bAuth, TpmCc, TpmiDhObject,
        TpmlPcrSelection, TpmtPublic,
    },
};

// TODO: implement single create method 

impl Context {
    pub(crate) fn create_and_load(
        &mut self,
        in_public: &TpmtPublic,
        auth: Tpm2bAuth,
        parent: &LoadedHandle,
        session_salt_handle: Option<TpmiDhObject>,
    ) -> Result<CreatedObject> {
        // use password session when session_salt_handle is None
        let mut request_params = Vec::new();

        marshal_tpm2b(&mut request_params, &TpmsSensitiveCreate::asymmetric(auth))?;
        marshal_tpm2b(&mut request_params, in_public)?;
        marshal_tpm2b(&mut request_params, Tpm2bData::default().as_bytes())?;
        TpmlPcrSelection::default().marshal(&mut request_params)?;

        let mut resources = CommandResources::default();
        let command_code = TpmCc::CREATE;

        let result = (|| {
            let (out_private, out_public, hmac_session_state) = match session_salt_handle {
                Some(_) => {
                    let mut sessions = self.prepare_sessions(
                        &mut resources,
                        TpmaSession::encrypt_decrypt().with_continue_session(),
                        Some(parent.authorization()),
                        session_salt_handle,
                        None,
                    )?;   
                    
                    let first_param = tpm2b_payload_mut(&mut request_params)?;
                    encrypt_command_parameter(&sessions, first_param)?;

                    update_command_hmacs(
                        &mut sessions,
                        command_code,
                        &[parent.name()],
                        &request_params,
                    )?;

                    let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);
                    let hmac_session = find_hmac_session(&sessions);        

                    let command = Command::new(command_code)
                        .with_handles([parent.handle().into()])
                        .with_authorizations(&authorizations)
                        .with_parameters(&request_params);

                    let response_body = self.submit(command)?;
                    resources.clear_policy_session();

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

            let (obj_handle, name) = self.load_handle(
                &out_private,
                &out_public,
                parent,
                session_salt_handle,
                hmac_session_state,
                Some(&mut resources),
            )?;

            Ok(CreatedObject {
                obj_handle: obj_handle.try_into()?,
                public: out_public,
                private: Some(out_private),
                name,
            })               
        })();

        self.finish_command(result, &mut resources)
    }

    pub(crate) fn create_primary(
        &mut self,
        primary_handle: TpmiRhHierarchy,
        in_public: &TpmtPublic,
        auth: Tpm2bAuth,
        primary_authorization: &Authorization,
        session_salt_handle: Option<TpmiDhObject>,
    ) -> Result<CreatedObject> {
        let mut request_params = Vec::new();

        marshal_tpm2b(
            &mut request_params,
            &TpmsSensitiveCreate::asymmetric(auth),
        )?;
        marshal_tpm2b(&mut request_params, in_public)?;
        marshal_tpm2b(&mut request_params, Tpm2bData::default().as_bytes())?;
        TpmlPcrSelection::default().marshal(&mut request_params)?;

        let mut resources = CommandResources::default();

        let command_code = TpmCc::CREATE_PRIMARY;
        let session_attrs = match session_salt_handle {
            Some(_) => TpmaSession::encrypt_decrypt(),
            None => TpmaSession::empty(),
        };

        let result = (|| {
            let mut sessions = self.prepare_sessions(
                &mut resources,
                session_attrs,
                Some(primary_authorization),
                session_salt_handle,
                None,
            )?;

            if session_salt_handle.is_some() {
                let first_param = tpm2b_payload_mut(&mut request_params)?;
                encrypt_command_parameter(&sessions, first_param)?;
            }

            update_command_hmacs(
                &mut sessions,
                command_code,
                &[&primary_handle.raw().to_be_bytes()],
                &request_params,
            )?;

            let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);

            let command = Command::new(command_code)
                .with_handles([primary_handle.into()])
                .with_authorizations(&authorizations)
                .with_parameters(&request_params);

            let response_body = self.submit(command)?;
            resources.clear_sessions();

            let mut response = CreatePrimaryResponse::parse(&response_body, auth_contexts.len())?;
            resources.add_transient_handle(response.object_handle.try_into()?);

            match session_salt_handle {
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

            let (obj_handle, out_public, name) = response.into_parts()?;

            Ok(CreatedObject {
                obj_handle: obj_handle.try_into()?,
                public: out_public.into(),
                private: None,
                name,
            })
        })();

        self.finish_command(result, &mut resources)
    }
}
