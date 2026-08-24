use crate::types::tpm::{Tpm2bDigest, TpmiRhHierarchy};

use super::super::commands::TpmSt;

#[derive(Clone)]
pub(in crate::backend::windows) struct TpmtTkCreation {
    tag: TpmSt,
    hierarchy: TpmiRhHierarchy,
    digest: Tpm2bDigest,
}

impl TpmtTkCreation {
    pub(in crate::backend::windows) fn new(
        hierarchy: TpmiRhHierarchy, 
        digest: Tpm2bDigest,
    ) -> Self {
        Self {
            tag: TpmSt::CREATION,
            hierarchy,
            digest,
        }
    }
}
