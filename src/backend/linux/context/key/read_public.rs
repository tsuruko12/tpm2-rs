use tss_esapi::{
    handles::{KeyHandle, ObjectHandle},
    structures::{Name, Public},
};

use crate::{Error, Result};

use super::Context;

impl Context {
    pub(super) fn validate_object_name(
        &mut self,
        handle: ObjectHandle,
        expected_name: &[u8],
    ) -> Result<()> {
        let name = self.ctx.tr_get_name(handle).map_err(Error::esapi)?;
        validate_name(name.value(), expected_name)
    }

    pub(super) fn read_object_name(&mut self, handle: impl Into<ObjectHandle>) -> Result<Name> {
        self.ctx.tr_get_name(handle.into()).map_err(Error::esapi)
    }

    fn read_object_public(&mut self, handle: KeyHandle) -> Result<(Public, Name, Name)> {
        self.ctx.read_public(handle).map_err(Error::from_tss_err)
    }
}

fn validate_name(name: &[u8], expected_name: &[u8]) -> Result<()> {
    if name != expected_name {
        return Err(Error::corrupted_store());
    }

    Ok(())
}
