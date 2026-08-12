use tracing::debug;

use crate::{
    Error, Result,
    types::{Authorization, TpmCc, TpmHandle, TpmiDhObject, TpmiDhPersistent, TpmiRhProvision},
};
use super::{
    Context, CommandResources, SessionSlots,
    session::{
        authorization_commands, response_auth_contexts, update_command_hmacs,
    },
};
use super::super::{
    codec::parse_response_params_and_authorizations,
    commands::Command,
    macros::reject_trailing_bytes,
    types::{TpmRc, TpmaSession, TpmiDhContext},
};

impl Context {
    pub(super) fn evict_control(
        &mut self,
        resources: &mut CommandResources,
        obj_handle: TpmiDhObject,
        persistent_handle: &mut TpmiDhPersistent,
        owner_authorization: &Authorization,
        session_salt_key: Option<TpmiDhObject>,
        search_end: Option<TpmiDhPersistent>,
    ) -> Result<()> {
        let command_code = TpmCc::EVICT_CONTROL;
        let owner_handle = TpmiRhProvision::OWNER;
        let handle_name = self.read_object_name(obj_handle)?;

        let result = (|| {
            let mut sessions = self.prepare_sessions(
                resources,
                TpmaSession::empty(),
                Some(owner_authorization),
                session_salt_key,
                None,
            )?;

            let response_body = loop {
                let request_parameter = persistent_handle.raw().to_be_bytes();
                let owner_name = owner_handle.raw().to_be_bytes();

                update_command_hmacs(
                    &mut sessions,
                    command_code,
                    &[&owner_name, &handle_name],
                    &request_parameter,
                )?;

                let authorizations = authorization_commands(&sessions);

                let command = Command::new(command_code)
                    .with_handles(vec![owner_handle.into(), obj_handle.into()])
                    .with_parameters(&request_parameter)
                    .with_authorizations(&authorizations);

                match self.submit(command) {
                    Ok(response_body) => {
                        resources.clear_sessions();
                        break response_body;
                    },
                    Err(err) => {
                        let raw_handle = persistent_handle.raw();

                        if err.tpm_rc() == Some(TpmRc::NV_DEFINED) {
                            if let Some(end) = search_end {
                                let next_handle = raw_handle + 1;

                                if next_handle > end.raw() {
                                    return Err(Error::PersistentHandleInUse(raw_handle));
                                }

                                *persistent_handle = TpmiDhPersistent::try_from(next_handle)?;
                                continue;
                            }
                            return Err(Error::PersistentHandleInUse(raw_handle));
                        }
                        return Err(err);
                    }
                }
            };

            let auth_contexts = response_auth_contexts(&sessions);
            let (returned_params, auth_responses) = parse_response_params_and_authorizations(
                &mut response_body.as_slice(),
                auth_contexts.len(),
            )?;

            if !returned_params.is_empty() {
                reject_trailing_bytes!(returned_params.len());
            }

            auth_contexts
                .iter()
                .zip(auth_responses.iter())
                .filter(|(auth_context, _)| auth_context.requires_hmac())
                .try_for_each(|(auth_context, auth_response)| {
                    auth_context.verify_hmac(command_code, &returned_params, auth_response)
                })
        })();

        self.finish_command(result, resources)
    }

    pub(super) fn release_resources(&mut self, resources: &mut CommandResources) -> Result<()> {
        self.flush_sessions(&mut resources.sessions)?;
        self.flush_handles(&mut resources.transient_handles)?;

        Ok(())
    }

    pub(super) fn cleanup_resources(&mut self, resources: &mut CommandResources) {
        let _ = self.flush_sessions(&mut resources.sessions);
        let _ = self.flush_handles(&mut resources.transient_handles);
    }

    pub(super) fn flush_sessions(&mut self, sessions: &mut SessionSlots) -> Result<()> {
        let mut first_err = None;

        for session in sessions {
            let Some(handle) = *session else {
                continue;
            }; 

            match self.flush_context(handle) {
                Ok(()) => *session = None,
                Err(e) => {
                    first_err.get_or_insert(e);
                    debug!(?handle, "failed to flush TPM session");
                }
            }
        }

        first_err.map_or(Ok(()), Err)
    }

    // memo: assign NULL for flushed handles
    pub(super) fn flush_handles(&mut self, handles: &mut Vec<TpmiDhObject>) -> Result<()> {
        let mut first_err = None;
        let mut remaining = Vec::new();

        while let Some(obj_handle) = handles.pop() {
            let handle = TpmiDhContext::try_from(obj_handle)
                .expect("handle must be a transient object handle");

            if let Err(e) = self.flush_context(handle) {
                first_err.get_or_insert(e);
                remaining.push(obj_handle);

                debug!(?handle, "failed to flush TPM handle");
            }
        }

        *handles = remaining;

        first_err.map_or(Ok(()), Err)
    }

    fn flush_context(&mut self, handle: impl Into<TpmiDhContext>) -> Result<()> {
        let command =
            Command::new(TpmCc::FLUSH_CONTEXT).with_handles([TpmHandle::from(handle.into())]);

        let response_body = self.submit(command)?;

        if !response_body.is_empty() {
            reject_trailing_bytes!(response_body.len());
        }

        Ok(())
    }
}
