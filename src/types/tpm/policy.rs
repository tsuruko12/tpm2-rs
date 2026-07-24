use crate::macros::tpm_list_type;

use super::algorithm::TpmiAlgHash;

tpm_list_type!(TpmlPcrSelection(TpmsPcrSelection););

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmsPcrSelection {
    hash: TpmiAlgHash,
    pcr_select: Vec<u8>,
}

impl TpmsPcrSelection {
    pub(crate) fn new(hash: TpmiAlgHash, pcr_select: Vec<u8>) -> Self {
        Self { hash, pcr_select }
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
}
