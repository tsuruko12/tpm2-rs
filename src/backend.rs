use rand::{RngCore, rngs::OsRng};

use crate::{
    Error, Result,
    types::{SymmetricKeyBits, tpm::Tpm2bPublicKeyRsa},
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) type BackendContext = linux::Context;
#[cfg(target_os = "windows")]
pub(crate) type BackendContext = windows::Context;

fn generate_sym_key(key_bits: SymmetricKeyBits) -> Result<Tpm2bPublicKeyRsa> {
    let key_len = match key_bits {
        SymmetricKeyBits::Bits128 => 16,
        SymmetricKeyBits::Bits256 => 32,
    };

    let mut key = vec![0u8; key_len];
    OsRng
        .try_fill_bytes(key.as_mut_slice())
        .map_err(Error::random_generation)?;

    Ok(key
        .try_into()
        .expect("generated symmetric key size must not exceed Tpm2bPublicKeyRsa::MAX_BYTES")
    )
}
