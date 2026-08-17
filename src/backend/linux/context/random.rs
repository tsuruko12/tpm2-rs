use tracing::debug;
use tss_esapi::handles::KeyHandle;

use super::{CommandResources, Context};
use crate::{
    error::{Error, Result},
    types::TpmaSession,
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

            while bytes.len() < num_bytes {
                let remaining = num_bytes - bytes.len();
                let bytes_requested = remaining.min(u16::MAX as usize) as u16;

                self.prepare_sessions(
                    &mut resources,
                    None,
                    TpmaSession::encrypt().with_continue_session(),
                    Some(session_salt_handle),
                )?;

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

                if chunk.len() > bytes_requested as usize {
                    debug!("TPM returned more random bytes than requested");
                    return Err(Error::InvalidData);
                }

                bytes.extend_from_slice(&chunk);
            }

            resources.release(self)?;

            Ok(bytes)
        })();

        self.finish_command(result, &mut resources)
    }
}
