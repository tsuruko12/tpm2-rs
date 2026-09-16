use tracing::debug;
use tss_esapi::handles::ObjectHandle;

use crate::{Error, Result, types::tpm::Tpm2bName};
use super::Context;

impl Context {
    pub(super) fn read_obj_name(
        &mut self, 
        obj_handle: ObjectHandle,
    ) -> Result<Tpm2bName> {
        self.ctx
            .tr_get_name(obj_handle)
            .map(Into::into)
            .map_err(Error::esapi)
    }
}

pub(super) fn validate_obj_name(name: &[u8], expected_name: &[u8]) -> Result<()> {
    if name != expected_name {
        debug!("stored TPM object name does not match");
        return Err(Error::corrupted_store())
    }

    Ok(())
}

