use super::super::{
    codec::parse_response_params_and_authorizations,
    commands::Command,
    macros::reject_trailing_bytes,
    types::{TpmRc, TpmaSession, TpmiDhContext, TpmiShPolicy},
};
use super::{
    Context,
    session::{
        CpHashData, ResponseAuthContext, split_prepared_sessions, update_command_hmacs,
        verify_response_hmac,
    },
};
use crate::{
    Error, Result,
    types::{Authorization, TpmCc, TpmHandle, TpmiDhObject, TpmiDhPersistent, TpmiRhProvision},
};

impl Context {
    pub(crate) fn evict_control(
        &mut self,
        handle: TpmiDhObject,
        persistent_handle: &mut TpmiDhPersistent,
        owner_authorization: &Authorization,
        session_salt_key_handle: Option<TpmiDhObject>,
        search_end: Option<TpmiDhPersistent>,
    ) -> Result<()> {
        let mut sessions = self.prepare_sessions(
            owner_authorization,
            TpmaSession::CONTINUE_SESSION, // memo: should be empty attrs
            session_salt_key_handle,
            None,
        )?;

        let command_code = TpmCc::EVICT_CONTROL;
        let owner_handle = TpmiRhProvision::OWNER;
        let handle_name = self.read_object_name(handle)?;

        let (response_body, auth_contexts) = loop {
            let request_parameter = persistent_handle.raw().to_be_bytes();

            if session_salt_key_handle.is_some() {
                let cp_hash_data = CpHashData {
                    command_code,
                    handle_names: &[&owner_handle.raw().to_be_bytes(), &handle_name],
                    parameters: &request_parameter,
                };
                update_command_hmacs(&mut sessions, &cp_hash_data)?;
            }

            let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);

            let command = Command::new(command_code)
                .with_handles(vec![owner_handle.into(), handle.into()])
                .with_parameters(&request_parameter)
                .with_authorizations(&authorizations);

            match self.submit(command) {
                Ok(response_body) => break (response_body, auth_contexts),
                Err(err) => {
                    let raw_handle = persistent_handle.raw();

                    if err.tpm_rc() == Some(TpmRc::NV_DEFINED) {
                        if let Some(end) = search_end {
                            let handle = raw_handle + 1;

                            if handle > end.raw() {
                                return Err(Error::PersistentHandleInUse(raw_handle));
                            }

                            *persistent_handle = TpmiDhPersistent::try_from(handle)?;
                            continue;
                        }
                        return Err(Error::PersistentHandleInUse(raw_handle));
                    }
                    return Err(err);
                }
            }
        };

        self.clear_policy_session();
        self.flush_sessions()?;

        let (returned_params, auth_responses) = parse_response_params_and_authorizations(
            &mut response_body.as_slice(),
            auth_contexts.len(),
        )?;

        if !returned_params.is_empty() {
            reject_trailing_bytes!(returned_params.len());
        }

        if session_salt_key_handle.is_some() {
            for (auth_context, auth_response) in auth_contexts.iter().zip(auth_responses) {
                let ResponseAuthContext::Hmac(context) = auth_context else {
                    continue;
                };

                verify_response_hmac(
                    context.session_value,
                    command_code,
                    &[],
                    context.nonce_caller.as_bytes(),
                    &auth_response,
                )?;
            }
        }

        Ok(())
    }

    pub(super) fn flush_sessions(&mut self) -> Result<()> {
        for idx in 0..self.sessions.len() {
            if let Some(handle) = self.sessions[idx] {
                self.flush_context(handle)?;
                self.sessions[idx] = None;
            }
        }

        Ok(())
    }

    pub(super) fn clear_sessions(&mut self) {
        self.sessions.fill(None);
    }

    pub(super) fn clear_policy_session(&mut self) {
        for idx in 0..self.sessions.len() {
            if let Some(handle) = self.sessions[idx] {
                if (TpmiShPolicy::FIRST..=TpmiShPolicy::LAST).contains(&handle.raw()) {
                    self.sessions[idx] = None;
                }
            }
        }
    }

    pub(super) fn flush_handle(&mut self, handle: TpmiDhObject) -> Result<()> {
        if handle.is_transient() {
            let handle = TpmiDhContext::try_from(handle)?;
            return self.flush_context(handle);
            // memo: should clear session slots as well
        }

        Ok(())
    }

    fn flush_context(&mut self, handle: impl Into<TpmiDhContext>) -> Result<()> {
        let command =
            Command::new(TpmCc::FLUSH_CONTEXT).with_handles([TpmHandle::from(handle.into())]);

        let response_body = self.submit(command).map_err(Error::session_flush)?;

        if !response_body.is_empty() {
            reject_trailing_bytes!(response_body.len());
        }

        Ok(())
    }
}
