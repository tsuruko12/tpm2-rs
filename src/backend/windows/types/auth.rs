use crate::{
    macros::{tpm2b_bytes_type, tpm2b_secret_type}, 
    types::{Tpm2bAuth, Tpm2bDigest, TpmAlgId, TpmlPcrSelection}
};
use super::{TpmaLocality, Tpm2bName};

tpm2b_bytes_type!(Tpm2bNonce);
tpm2b_bytes_type!(Tpm2bData);
tpm2b_bytes_type!(Tpm2bCreationData(TpmsCreationData));
tpm2b_secret_type!(Tpm2bSensitiveCreate(TpmsSensitiveCreate));
tpm2b_secret_type!(Tpm2bSensitiveData);
tpm2b_secret_type!(Tpm2bPrivate);

#[derive(Debug, Clone)]
pub(crate) struct TpmsCreationData {
    pcr_select: TpmlPcrSelection,
    pcr_digest: Tpm2bDigest,
    locality: TpmaLocality,
    parent_name_alg: TpmAlgId,
    parent_name: Tpm2bName,
    parent_qualified_name: Tpm2bName,
    outside_info: Tpm2bData,
}

impl TpmsCreationData {
    pub(crate) fn new(
        pcr_select: TpmlPcrSelection,
        pcr_digest: Tpm2bDigest,
        locality: TpmaLocality,
        parent_name_alg: TpmAlgId,
        parent_name: Tpm2bName,
        parent_qualified_name: Tpm2bName,
        outside_info: Tpm2bData,
    ) -> Self {
        Self {
            pcr_select,
            pcr_digest,
            locality,
            parent_name_alg,
            parent_name,
            parent_qualified_name,
            outside_info,
        }
    }

    pub(crate) fn pcr_select(&self) -> &TpmlPcrSelection {
        &self.pcr_select
    }

    pub(crate) fn pcr_digest(&self) -> &Tpm2bDigest {
        &self.pcr_digest
    }

    pub(crate) fn locality(&self) -> &TpmaLocality {
        &self.locality
    }

    pub(crate) fn parent_name_alg(&self) -> &TpmAlgId {
        &self.parent_name_alg
    }

    pub(crate) fn parent_name(&self) -> &Tpm2bName {
        &self.parent_name
    }

    pub(crate) fn parent_qualified_name(&self) -> &Tpm2bName {
        &self.parent_qualified_name
    }

    pub(crate) fn outside_info(&self) -> &Tpm2bData {
        &self.outside_info
    }
}

impl TpmsCreationData {
    pub(crate) fn default() -> Self {
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

impl Tpm2bSensitiveCreate {
    pub(crate) fn inner(&self) -> &TpmsSensitiveCreate {
        &self.0
    }
}

// minimum marshaled size is 4 bytes: two TPM2B size fields
#[derive(zeroize::Zeroize)]
pub(crate) struct TpmsSensitiveCreate {
    user_auth: Tpm2bAuth,
    data: Tpm2bSensitiveData,
}

impl TpmsSensitiveCreate {
    pub(crate) fn asymmetric(user_auth: Tpm2bAuth) -> Self {
        Self {
            user_auth,
            data: Tpm2bSensitiveData::default(),
        }
    }

    pub(crate) fn as_parts(&self) -> (&Tpm2bAuth, &Tpm2bSensitiveData) {
        (&self.user_auth, &self.data)
    }
}
