use crate::types::Tpm2bDigest;

use super::super::{commands::TpmSt, types::TpmiRhHierarchy};

#[derive(Debug, Clone)]
pub(crate) struct TpmtTkCreation {
    tag: TpmSt,
    hierarchy: TpmiRhHierarchy,
    digest: Tpm2bDigest,
}

impl TpmtTkCreation {
    pub(crate) fn new(
        tag: TpmSt,
        hierarchy: TpmiRhHierarchy,
        digest: Tpm2bDigest,
    ) -> Self {
        Self {
            tag,
            hierarchy,
            digest,
        }
    }
}