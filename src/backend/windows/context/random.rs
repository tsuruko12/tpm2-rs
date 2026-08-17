use tracing::debug;

use super::super::{codec::GetRandomResponse, commands::Command};
use super::{
    CommandResources, Context,
    session::{decrypt_response_parameter, split_prepared_sessions, update_command_hmacs},
};
use crate::{
    error::{Error, Result},
    types::{TpmCc, TpmaSession, TpmiDhObject},
};

impl Context {
    pub(crate) fn get_random(
        &mut self,
        num_bytes: usize,
        session_salt_handle: TpmiDhObject,
    ) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(num_bytes)
            .map_err(|_| Error::resource_exhausted("failed to allocate random output buffer"))?;

        while bytes.len() < num_bytes {
            let remaining = num_bytes - bytes.len();
            let bytes_requested = remaining.min(u16::MAX as usize) as u16;
            let chunk = self.get_random_chunk(bytes_requested, session_salt_handle)?;

            if chunk.is_empty() {
                debug!("TPM returned no random bytes");
                return Err(Error::InvalidData);
            }

            if chunk.len() > bytes_requested as usize {
                debug!("TPM returned more random bytes than requested");
                return Err(Error::InvalidData);
            }

            bytes.extend_from_slice(&chunk);
        }

        Ok(bytes)
    }

    fn get_random_chunk(
        &mut self,
        bytes_requested: u16,
        session_salt_handle: TpmiDhObject,
    ) -> Result<Vec<u8>> {
        let request_params = bytes_requested.to_be_bytes();

        let mut resources = CommandResources::default();
        let command_code = TpmCc::GET_RANDOM;

        let result = (|| {
            let mut sessions = self.prepare_sessions(
                &mut resources,
                TpmaSession::encrypt(),
                None,
                Some(session_salt_handle),
                None,
            )?;

            update_command_hmacs(&mut sessions, command_code, &[], &request_params)?;

            let (authorizations, auth_contexts) = split_prepared_sessions(&sessions);

            let command = Command::new(command_code)
                .with_authorizations(&authorizations)
                .with_parameters(&request_params);

            let response_body = self.submit(command)?;
            resources.clear_sessions();

            let mut response = GetRandomResponse::parse(&response_body, auth_contexts.len())?;

            decrypt_response_parameter(
                command_code,
                &mut response.parameters,
                &auth_contexts,
                &response.authorizations,
            )?;

            response.into_parts().map(|bytes| bytes.into_bytes())
        })();

        self.finish_command(result, &mut resources)
    }
}
