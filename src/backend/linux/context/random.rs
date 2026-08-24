use tracing::debug;
use tss_esapi::handles::KeyHandle;

use super::{CommandResources, Context};
use crate::{
    error::{Error, Result},
    types::tpm::TpmaSession,
};

impl Context {
    pub(crate) fn get_random(
        &mut self,
        num_bytes: usize,
        session_salt_handle: KeyHandle,
    ) -> Result<Vec<u8>> {
        let mut resources = CommandResources::default();
        resources.add_persistent_handle(session_salt_handle.into());

        let result = (|| {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(num_bytes).map_err(|_| {
                Error::resource_exhausted("failed to allocate random output buffer")
            })?;

            self.prepare_sessions(
                resources,
                TpmaSession::encrypt().with_continue_session(),
                None,
                Some(session_salt_handle),
            )?;

            while bytes.len() < num_bytes {
                let remaining = num_bytes - bytes.len();
                let bytes_requested = remaining.min(u16::MAX as usize) as u16;

                let chunk = self.get_random_chunk(
                    &mut resources,
                    bytes_requested,
                )?;

                bytes.extend_from_slice(&chunk);
            }

            Ok(bytes)
        })();

        self.finish_command(result, &mut resources)
    }

    fn get_random_chunk(
        &mut self,
        resources: &mut CommandResources,
        bytes_requested: u16,
    ) -> Result<Vec<u8>> {
        let chunk = self
            .ctx
            .execute_with_session(resources.find_hmac_session(), |ctx| {
                ctx.get_random(bytes_requested as usize)
            })
            .map(|bytes| bytes.to_vec())
            .map_err(Error::from_tss_err)?;

        resources.flush_sessions(self)?;

        if chunk.is_empty() {
            debug!("TPM returned no random bytes");
            return Err(Error::InvalidData);
        }

        Ok(chunk)
    }
}
