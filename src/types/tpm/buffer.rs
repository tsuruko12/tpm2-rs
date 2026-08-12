use sha2::{Sha256, Digest};

use crate::{macros::{impl_buffer_methods, impl_try_from_bytes, tpm2b_bytes_type, tpm2b_zeroize_type}};
use super::sensitive::Tpm2bSensitive;

const TPM2B_SIZE_BYTES: usize = 2;

tpm2b_zeroize_type!(Tpm2bPrivate);

impl Tpm2bPrivate {
    pub(crate) const MAX_BYTES: usize =
        (Tpm2bDigest::MAX_BYTES * 2)
        + Tpm2bSensitive::MAX_BYTES
        + (TPM2B_SIZE_BYTES * 3);
}

struct _Private {
    integrity_outer: Tpm2bDigest,
    integrity_inner: Tpm2bDigest,
    sensitive: Tpm2bSensitive,
}

#[derive(Debug, Default, Clone, zeroize::Zeroize)]
pub(crate) struct Tpm2bDigest(Vec<u8>);

impl_buffer_methods!(Tpm2bDigest);
impl_try_from_bytes!(Tpm2bDigest);

impl Tpm2bDigest {
    pub(crate) const MAX_BYTES: usize = 64;
}

tpm2b_zeroize_type!(Tpm2bAuth);

impl Tpm2bAuth {
    pub(crate) const MAX_BYTES: usize = Tpm2bDigest::MAX_BYTES;

    pub(crate) fn normalize_sha256(value: &[u8]) -> Self {
        if value.len() <= Sha256::output_size() {
            Self(value.to_vec())
        } else {
            Self(Sha256::digest(value).to_vec())
        }        
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self(self.as_bytes().to_vec())
    }
}

tpm2b_bytes_type!(Tpm2bLabel); 

impl Tpm2bLabel {
    const MAX_BYTES: usize = 32;
}