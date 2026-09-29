use super::{buffer::Tpm2bDigest, handle::TpmiRhHierarchy, tag::TpmSt};

#[derive(Clone)]
pub(crate) struct TpmtTkHashCheck {
    tag: TpmSt, // TPM_ST_HASHCHECK
    hierarchy: TpmiRhHierarchy,
    digest: Tpm2bDigest,
}

impl std::fmt::Debug for TpmtTkHashCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmtTkHashCheck")
            .field("tag", &self.tag)
            .field("hierarchy", &self.hierarchy)
            .finish_non_exhaustive()
    }
}

impl TpmtTkHashCheck {
    pub(crate) fn new(hierarchy: TpmiRhHierarchy, digest: Tpm2bDigest) -> Self {
        Self {
            tag: TpmSt::HASHCHECK,
            hierarchy,
            digest,
        }
    }

    pub(crate) fn null() -> Self {
        Self {
            tag: TpmSt::HASHCHECK,
            hierarchy: TpmiRhHierarchy::NULL,
            digest: Tpm2bDigest::default(),
        }
    }

    pub(crate) fn tag(&self) -> TpmSt {
        self.tag
    }

    pub(crate) fn hierarchy(&self) -> TpmiRhHierarchy {
        self.hierarchy
    }

    pub(crate) fn digest(&self) -> &Tpm2bDigest {
        &self.digest
    }
}
