use tracing::debug;

use super::{Command, CommandResources, Context, GetRandomResponse, TpmsAuthCommand};
use crate::{
    error::{Error, Result},
    types::tpm::{Tpm2bDigest, TpmCc, TpmaSession, TpmiDhObject},
};

const RESPONSE_HANDLE_COUNT: usize = 0;

impl Context {
    pub(crate) fn get_random(
        &mut self,
        num_bytes: usize,
        session_salt_handle: TpmiDhObject,
    ) -> Result<Vec<u8>> {
        let mut resources = CommandResources::default();

        let mut bytes = Vec::new();

        let result = (|| {
            while bytes.len() < num_bytes {
                let remaining = num_bytes - bytes.len();
                let bytes_requested = remaining.min(u16::MAX as usize) as u16;

                let authorization_area = self.prepare_sessions(
                    &mut resources,
                    TpmaSession::encrypt().with_continue_session(),
                    None,
                    Some(session_salt_handle),
                )?;

                let chunk =
                    self.get_random_chunk(bytes_requested, authorization_area, &mut resources)?;
                if chunk.is_empty() {
                    debug!("TPM returned no random bytes");
                    return Err(Error::InvalidData);
                }

                bytes
                    .try_reserve(chunk.len())
                    .map_err(|_| Error::resource_exhausted(
                        "failed to allocate random output buffer"
                    ))?;
                bytes.extend_from_slice(chunk.as_bytes());
            }

            resources.flush_sessions(self)?;

            Ok(bytes)
        })();

        self.cleanup_on_err(result, &mut resources)
    }

    fn get_random_chunk(
        &mut self,
        bytes_requested: u16,
        authorization_area: Vec<TpmsAuthCommand>,
        resources: &mut CommandResources,
    ) -> Result<Tpm2bDigest> {
        let mut command_params = bytes_requested.to_be_bytes();
        let mut command = Command::new(TpmCc::GET_RANDOM)
            .with_authorization_area(authorization_area)
            .with_parameters(&mut command_params);

        let response_body = self.submit(&mut command, RESPONSE_HANDLE_COUNT, resources)?;

        Ok(GetRandomResponse::try_from(response_body)?.random_bytes)
    }
}
