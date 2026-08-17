use tracing::debug;
use tss_esapi::{
    handles::{KeyHandle, ObjectHandle},
    structures::{Name, Public},
};

use crate::{Error, Result, types::Tpm2bName};
use super::Context;

impl Context {
    pub(crate) fn validate_obj_name(
        &mut self,
        obj_handle: ObjectHandle,
        expected_name: &Tpm2bName,
        name: Option<&Tpm2bName>,
    ) -> Result<()> {
        match name {
            Some(name) => validate_name(name.as_bytes(), expected_name.as_bytes()),
            None => {
                let name = self.read_obj_name(obj_handle)?;
                validate_name(name.as_bytes(), expected_name.as_bytes())
            }
        }
    }

    pub(super) fn read_obj_name(
        &mut self, 
        obj_handle: ObjectHandle,
    ) -> Result<Tpm2bName> {
        self.ctx
            .tr_get_name(obj_handle)
            .map(Into::into)
            .map_err(Error::esapi)
    }

    fn read_obj_public(&mut self, handle: KeyHandle) -> Result<(Public, Name, Name)> {
        self.ctx.read_public(handle).map_err(Error::from_tss_err)
    }
}

fn validate_name(name: &[u8], expected_name: &[u8]) -> Result<()> {
    if name != expected_name {
        debug!("stored TPM object name does not match");
        return Err(Error::corrupted_store());
    }

    Ok(())
}
