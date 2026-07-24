use crate::{macros::tpm2b_bytes_type, types::{TpmtPublic, TpmuPublicId}};

tpm2b_bytes_type!(Tpm2bPublic(TpmtPublic));
tpm2b_bytes_type!(Tpm2bName);

impl Tpm2bPublic {
    pub(crate) fn unique(&self) -> &TpmuPublicId {
        self.0.unique()
    }
}