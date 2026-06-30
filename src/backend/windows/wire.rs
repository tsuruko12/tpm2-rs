use zeroize::Zeroizing;

use super::types::Uint16;
use crate::error::{Error, Result};

const TPM2B_SIZE_FIELD_SIZE: usize = 2;

pub(crate) fn unmarshal_tpm2b(bytes: &[u8]) -> Result<(Uint16, Zeroizing<Vec<u8>>)> {
    if bytes.len() < TPM2B_SIZE_FIELD_SIZE {
        return Err(Error::Internal("TPM2B value must contain a size field"));
    }

    let size = Uint16::from_be_bytes(bytes[..TPM2B_SIZE_FIELD_SIZE].try_into().unwrap()) as usize;

    let value = &bytes[TPM2B_SIZE_FIELD_SIZE..];

    if size != value.len() {
        return Err(Error::Internal("TPM2B value size does not match buffer length"));
    }

    Ok((size as Uint16, Zeroizing::new(value.to_vec())))
}