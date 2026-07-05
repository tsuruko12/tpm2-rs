use crate::{
    Error, Result,
    types::{CapabilityData, TpmCap},
};

use super::Context;

impl Context {
    pub(crate) fn get_capability_once(
        &mut self,
        capability: TpmCap,
        property: u32,
        property_count: u32,
    ) -> Result<(bool, CapabilityData)> {
        let (data, more) = self
            .ctx
            .get_capability(capability.into(), property, property_count)
            .map_err(|e| Error::from_tss_err(e))?;

        Ok((more, data.try_into()?))
    }
}
