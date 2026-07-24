use crate::types::{Authorization, TpmiDhObject};

pub(crate) struct LoadedParent {
    handle: TpmiDhObject,
    name: Vec<u8>,
    authorization: Authorization,
}

impl LoadedParent {
    pub(crate) fn new(
        handle: TpmiDhObject, 
        name: impl Into<Vec<u8>>, 
        authorization: Authorization,
    ) -> Self {
        Self { handle, name: name.into(), authorization }
    }

    pub(crate) fn handle(&self) -> TpmiDhObject {
        self.handle
    }

    pub(crate) fn name(&self) -> &[u8] {
        &self.name
    }

    pub(crate) fn authorization(&self) -> &Authorization {
        &self.authorization
    }
}
