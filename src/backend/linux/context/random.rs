use tss_esapi::handles::KeyHandle;

use super::{CommandResources, Context};
use crate::{
    error::{Error, Result},
    types::TpmaSession,
};

impl Context {
    pub(crate) fn get_random(
        &mut self,
        bytes_requested: u16,
        session_salt_key: KeyHandle,
    ) -> Result<Vec<u8>> {
        let mut resources = CommandResources::default();

        let result = (|| {
            self.prepare_sessions(
                &mut resources,
                None,
                TpmaSession::encrypt().with_continue_session(),
                Some(session_salt_key),
            )?;

            self
                .ctx
                .execute_with_session(resources.find_hmac_session(), |ctx| {
                    ctx.get_random(bytes_requested as usize)
                })
                .map(|bytes| bytes.to_vec())
                .map_err(Error::from_tss_err)
        })();

        self.finish_command(result, &mut resources)
    }
}
