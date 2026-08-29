use tss_esapi::{
    constants::CapabilityType,
    structures::CapabilityData,
};

use crate::{Error, Result};

use super::Context;

impl Context {
    pub(super) fn get_capability_once(
        &mut self,
        capability: CapabilityType,
        property: u32,
        property_count: u32,
    ) -> Result<(CapabilityData, bool)> {
        self.ctx
            .get_capability(capability, property, property_count)
            .map_err(|e| Error::from_tss_err(e))
    }
}
