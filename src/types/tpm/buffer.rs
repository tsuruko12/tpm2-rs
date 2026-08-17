use sha2::{Sha256, Digest};
use zeroize::Zeroizing;

use crate::{macros::{tpm2b_type, tpm2b_zeroize_type}};
use super::sensitive::Tpm2bSensitive;

const TPM2B_SIZE_BYTES: usize = 2;

tpm2b_zeroize_type!(
    Tpm2bPrivate,
    (Tpm2bDigest::MAX_BYTES * 2) + Tpm2bSensitive::MAX_BYTES + (TPM2B_SIZE_BYTES * 3)
);

struct _Private {
    integrity_outer: Tpm2bDigest,
    integrity_inner: Tpm2bDigest,
    sensitive: Tpm2bSensitive,
}

tpm2b_zeroize_type!(Tpm2bDigest, 64);

impl Clone for Tpm2bDigest {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

tpm2b_zeroize_type!(Tpm2bAuth, Tpm2bDigest::MAX_BYTES);

impl Tpm2bAuth {
    pub(crate) fn normalize_sha256(value: &[u8]) -> Self {
        if value.len() <= Sha256::output_size() {
            Self(Zeroizing::new(value.to_vec()))
        } else {
            Self(Zeroizing::new(Sha256::digest(value).to_vec()))
        }        
    }

    pub(crate) fn clone(&self) -> Self {
        Self(Zeroizing::new(self.as_bytes().to_vec()))
    }
}

tpm2b_type!(Tpm2bLabel, 32); 
