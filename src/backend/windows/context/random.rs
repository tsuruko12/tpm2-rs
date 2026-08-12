use super::super::{codec::GetRandomResponse, commands::Command};
use super::{
    CommandResources, Context,
    session::{decrypt_response_parameter, split_prepared_sessions, update_command_hmacs},
};
use crate::{
    error::Result,
    types::{TpmCc, TpmaSession, TpmiDhObject},
};

impl Context {
    pub(crate) fn get_random(
        &mut self,
        bytes_requested: u16,
        session_salt_key: TpmiDhObject,
    ) -> Result<Vec<u8>> {
        let request_params = bytes_requested.to_be_bytes();

        let mut resources = CommandResources::default();
        let command_code = TpmCc::GET_RANDOM;

        let result = (|| {
            let mut sessions = self.prepare_sessions(
                &mut resources,
                TpmaSession::encrypt(),
                None,
                Some(session_salt_key),
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
