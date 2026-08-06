use tss_esapi::{
    constants::CapabilityType,
    interface_types::algorithm::HashingAlgorithm,
    structures::{CapabilityData, PcrSelectSize},
};

use crate::{Error, Result};

use super::Context;

impl Context {
    pub(crate) fn get_capability_once(
        &mut self,
        capability: CapabilityType,
        property: u32,
        property_count: u32,
    ) -> Result<(CapabilityData, bool)> {
        self.ctx
            .get_capability(capability, property, property_count)
            .map_err(|e| Error::from_tss_err(e))
    }

    pub(super) fn get_sha256_pcr_select_size(&mut self) -> Result<PcrSelectSize> {
        let (data, _) = self.get_capability_once(CapabilityType::AssignedPcr, 0, 0)?;

        let CapabilityData::AssignedPcr(selection_list) = data else {
            tracing::debug!("unexpected capability data for AssignedPcr");
            return Err(Error::InvalidData);
        };

        for selection in selection_list.get_selections() {
            if selection.hashing_algorithm() == HashingAlgorithm::Sha256 {
                return Ok(selection.size_of_select());
            }
        }

        Err(Error::unsupported("SHA-256 PCR bank is not supported"))
    }
}
