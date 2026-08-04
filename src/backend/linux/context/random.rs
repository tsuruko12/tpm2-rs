use tss_esapi::handles::KeyHandle;

use crate::{error::{Error, Result}, types::TpmaSession};
use super::{Context, CommandResources};

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
                TpmaSession::encrypt(), 
                Some(session_salt_key),
            )?;

            let random_bytes = self.ctx.execute_with_session(resources.find_hmac_session(), |ctx| {
                ctx.get_random(bytes_requested as usize)           
            })
            .map_err(Error::from_tss_err)?;

            resources.clear_sessions();

            Ok(random_bytes.to_vec())
        })();

        self.finish_command(result, &mut resources)
    }
}
