use super::TpmaLocality;
use crate::{
    Error, Result, macros::{impl_tpm2b_inner_codec, tpm2b_type, tpm2b_zeroize_type},
    types::tpm::{Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bSensitiveData, TpmAlgId, TpmHandle,
        TpmiAlgHash, TpmlPcrSelection, TpmtHa},
};

tpm2b_type!(Tpm2bNonce, Tpm2bDigest::MAX_BYTES);

tpm2b_type!(Tpm2bData, TpmtHa::MAX_BYTES);

tpm2b_type!(Tpm2bCreationData(TpmsCreationData));

tpm2b_zeroize_type!(Tpm2bSensitiveCreate(TpmsSensitiveCreate), TpmsSensitiveCreate::MAX_BYTES);
impl_tpm2b_inner_codec!(Tpm2bSensitiveCreate(TpmsSensitiveCreate));


#[derive(Clone)]
pub(in crate::backend::windows) struct TpmsCreationData {
    pcr_select: TpmlPcrSelection,
    pcr_digest: Tpm2bDigest,
    locality: TpmaLocality,
    parent_name_alg: TpmAlgId,
    parent_name: Tpm2bName,
    parent_qualified_name: Tpm2bName,
    outside_info: Tpm2bData,
}

impl std::fmt::Debug for TpmsCreationData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmsCreationData")
            .field("pcr_select", &self.pcr_select)
            .field("locality", &self.locality)
            .field("parent_name_alg", &self.parent_name_alg)
            .field("parent_name", &self.parent_name)
            .field("parent_qualified_name", &self.parent_qualified_name)
            .finish_non_exhaustive()
    }
}

impl TpmsCreationData {
    pub(in crate::backend::windows) fn new(
        pcr_select: TpmlPcrSelection,
        pcr_digest: Tpm2bDigest,
        locality: TpmaLocality,
        parent_name_alg: TpmAlgId,
        parent_name: Tpm2bName,
        parent_qualified_name: Tpm2bName,
        outside_info: Tpm2bData,
    ) -> Result<Self> {
        if pcr_select.is_empty() && !pcr_digest.is_empty() {
            return Err(Error::invalid_param("pcrDigest must be empty when pcrSelect is empty"));
        }

        let expected_name_size = if parent_name_alg == TpmAlgId::Null {
            size_of::<TpmHandle>()
        } else {
            let digest_size = parent_name_alg.digest_size().ok_or_else(|| Error::invalid_param(
                "invalid parentNameAlg"
            ))?;
            size_of::<TpmiAlgHash>() + digest_size
        };

        if parent_name.size() != expected_name_size 
            || parent_qualified_name.size() != expected_name_size {
            return Err(Error::invalid_param(
                "parentName and parentQualifiedName sizes do not match parentNameAlg",
            ));
        }

        Ok(Self {
            pcr_select,
            pcr_digest,
            locality,
            parent_name_alg,
            parent_name,
            parent_qualified_name,
            outside_info,
        })
    }

    pub(in crate::backend::windows) fn pcr_select(&self) -> &TpmlPcrSelection {
        &self.pcr_select
    }

    pub(in crate::backend::windows) fn pcr_digest(&self) -> &Tpm2bDigest {
        &self.pcr_digest
    }

    pub(in crate::backend::windows) fn locality(&self) -> &TpmaLocality {
        &self.locality
    }

    pub(in crate::backend::windows) fn parent_name_alg(&self) -> &TpmAlgId {
        &self.parent_name_alg
    }

    pub(in crate::backend::windows) fn parent_name(&self) -> &Tpm2bName {
        &self.parent_name
    }

    pub(in crate::backend::windows) fn parent_qualified_name(&self) -> &Tpm2bName {
        &self.parent_qualified_name
    }

    pub(in crate::backend::windows) fn outside_info(&self) -> &Tpm2bData {
        &self.outside_info
    }
}

impl TpmsCreationData {
    pub(in crate::backend::windows) fn default() -> Self {
        Self {
            pcr_select: TpmlPcrSelection::default(),
            pcr_digest: Tpm2bDigest::default(),
            locality: TpmaLocality::empty(),
            parent_name_alg: TpmAlgId::Null,
            parent_name: Tpm2bName::default(),
            parent_qualified_name: Tpm2bName::default(),
            outside_info: Tpm2bData::default(),
        }
    }
}

pub(in crate::backend::windows) struct TpmsSensitiveCreate {
    pub(in crate::backend::windows) user_auth: Tpm2bAuth,
    pub(in crate::backend::windows) data: Tpm2bSensitiveData,
}

impl TpmsSensitiveCreate {
    pub(in crate::backend::windows) const MAX_BYTES: usize = Tpm2bAuth::MAX_BYTES 
        + Tpm2bSensitiveData::MAX_BYTES;

    pub(in crate::backend::windows) fn asymmetric(user_auth: Tpm2bAuth) -> Self {
        Self {
            user_auth,
            data: Tpm2bSensitiveData::default(),
        }
    }
}
