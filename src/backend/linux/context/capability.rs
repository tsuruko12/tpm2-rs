use crate::{Result, types::TpmCap};

use super::Context;

impl Context {
    pub(crate) fn read_capability_once(
        &mut self, 
        capability: TpmCap, 
        property: u32,
        property_count: u32,
    ) -> Result<(bool, Capabili)> {


        Ok(())
    }
}