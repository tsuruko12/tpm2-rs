use tracing::debug;

use crate::{Error, Result, macros::tpm_list_type, types::PcrSlot};
use super::algorithm::TpmiAlgHash;

const TPML_COUNT_SIZE: usize = 4;

tpm_list_type!(TpmlPcrSelection(TpmsPcrSelection));

impl TpmlPcrSelection {
    pub(crate) fn select_for_hash(&self, hash: TpmiAlgHash) -> Option<&[u8]> {
        self.items()
            .iter()
            .find(|selection| selection.hash == hash)
            .map(|selection| selection.pcr_select())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmsPcrSelection {
    hash: TpmiAlgHash,
    pcr_select: Vec<u8>,
}

impl TpmsPcrSelection {
    pub(crate) fn new(hash: TpmiAlgHash, pcr_select: Vec<u8>) -> Result<Self> {
        if pcr_select.len() > PcrSlot::SELECT_SIZE {
            debug!(
                pcr_select_size = pcr_select.len(),
                max_size = PcrSlot::SELECT_SIZE,
                "invalid PCR select size"
            );
            return Err(Error::InvalidData);
        }

        Ok(Self { hash, pcr_select })
    }

    pub(crate) fn hash(&self) -> TpmiAlgHash {
        self.hash
    }

    pub(crate) fn pcr_select(&self) -> &[u8] {
        &self.pcr_select
    }

    pub(crate) fn size_of_select(&self) -> usize {
        self.pcr_select.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pcr_select.is_empty()
    }
}
